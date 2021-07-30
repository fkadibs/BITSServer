"""
Originally SimpleBITSServer by Dor Azouri, refactored/migrated to Python3 by @fkadibs
"""
import os
import sys
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

# BITS server errors
class HResult(object):
    BG_ERROR_CONTEXT_REMOTE_FILE = hex(0x5)
    BG_E_TOO_LARGE = hex(0x80200020)
    E_ACCESSDENIED = hex(0x80070005)
    E_INVALIDARG = hex(0x80070057)
    ERROR_CODE_GENERIC = hex(0x1)
    ZERO = hex(0x0)

# BITS server status
class HTTPStatus(object):
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    REQUESTED_RANGE_NOT_SATISFIABLE = 416
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501

# exception handling
class BITSServerException(Exception):
    pass

class ClientProtocolNotSupported(BITSServerException):
    def __init__(self, supported_protocols):
        super(ClientProtocolNotSupported, self).__init__("Server supports neither of the requested protocol versions")
        self.requested_protocols = str(supported_protocols)

class ServerInternalError(BITSServerException):
    def __init__(self, internal_exception):
        super(ServerInternalError, self).__init__("Internal server error encountered")
        self.internal_exception = internal_exception

class InvalidFragment(BITSServerException):
    def __init__(self, last_range_end, new_range_start):
        super(ServerInternalError, self).__init__("Invalid fragment received on server")
        self.last_range_end = last_range_end
        self.new_range_start = new_range_start

class FragmentTooLarge(BITSServerException):
    def __init__(self, fragment_size):
        super(FragmentTooLarge, self).__init__("Oversized fragment received on server")
        self.fragment_size = fragment_size

class UploadAccessDenied(BITSServerException):
    def __init__(self):
        super(UploadAccessDenied, self).__init__("Write access to requested file upload is denied")

# BITS upload session
class BITSUploadSession(object):
    # holds the file paths that has an active upload session
    files_in_use = []

    def __init__(self, absolute_file_path, fragment_size_limit):
        self.fragment_size_limit = fragment_size_limit
        self.absolute_file_path = absolute_file_path
        self.fragments = []
        self.expected_file_length = -1

        # case the file already exists
        if os.path.exists(self.absolute_file_path):
            # case the file is actually a directory
            if os.path.isdir(self.absolute_file_path):
                self._status_code = HTTPStatus.FORBIDDEN
            # case the file is being uploaded in another active session
            elif self.absolute_file_path in BITSUploadSession.files_in_use:
                self._status_code = HTTPStatus.CONFLICT
            # case file exists on server - we overwrite the file with the new upload
            else:
                BITSUploadSession.files_in_use.append(self.absolute_file_path)
                self.__open_file()
        # case file does not exist but its parent folder does exist - we create the file
        elif os.path.exists(os.path.dirname(self.absolute_file_path)):
            BITSUploadSession.files_in_use.append(self.absolute_file_path)
            self.__open_file()
        # case file does not exist nor its parent folder - we don't create the directory tree
        else:
            self._status_code = HTTPStatus.FORBIDDEN

    def __open_file(self):
        try:
            self.file = open(self.absolute_file_path, "wb")
            self._status_code = HTTPStatus.OK
        except Exception:
            self._status_code = HTTPStatus.FORBIDDEN

    def get_last_status_code(self):
        return self._status_code

    def add_fragment(self, file_total_length, range_start, range_end, data):
        """
        Applies new fragment received from client to the upload session.
        Returns a boolean: is the new fragment last in session
        """
        # check if fragment size exceeds server limit
        if self.fragment_size_limit < range_end - range_start:
            raise FragmentTooLarge(range_end - range_start)

        # case new fragment is the first fragment in this session
        if self.expected_file_length == -1:
            self.expected_file_length = file_total_length

        last_range_end = self.fragments[-1]['range_end'] if self.fragments else -1
        if last_range_end + 1 < range_start:
            # case new fragment's range is not contiguous with the previous fragment
            # will cause the server to respond with status code 416
            raise InvalidFragment(last_range_end, range_start)
        elif last_range_end + 1 > range_start:
            # case new fragment partially overlaps last fragment
            # BITS protocol states that server should treat only the non-overlapping part
            range_start = last_range_end + 1

        self.fragments.append({'range_start': range_start,
                               'range_end': range_end,
                               'data': data
                               })

        # case new fragment is the first fragment in this session,
        # we write the final uploaded data to file
        if range_end + 1 == self.expected_file_length:
            for frg in self.fragments:
                self.file.write(frg['data'])

    def close(self):
        self.file.flush()
        self.file.close()
        BITSUploadSession.files_in_use.remove(self.absolute_file_path)

# BITS Base Request Handler
class BITSRequestHandler(BaseHTTPRequestHandler):
    # BITS Protocol header keys
    SESSION_ID = 'BITS-Session-Id'
    ERROR_CONTEXT = 'BITS-Error-Context'
    ERROR_CODE = 'BITS-Error-Code'
    PACKET_TYPE = 'BITS-Packet-Type'
    SUPPORTED_PROTOCOLS = 'BITS-Supported-Protocols'
    PROTOCOL = 'BITS-Protocol'

    # HTTP Protocol header keys
    ACCEPT_ENCODING = 'Accept-Encoding'
    CONTENT_NAME = 'Content-Name'
    CONTENT_LENGTH = 'Content-Length'
    CONTENT_RANGE = 'Content-Range'
    CONTENT_ENCODING = 'Content-Encoding'

    # http handler parameters
    protocol_version = "HTTP/1.1"
    # The only existing protocol version to date
    supported_protocols = ["{7df0354d-249b-430f-820d-3d2a9bef4931}"]
    fragment_size_limit = 100*1024*1024  # bytes
    base_dir = os.getcwd()

    def __send_response(self, headers_dict={}, status_code=HTTPStatus.OK, data=""):
        """
        Sends server response w/ headers and status code
        """
        self.send_response(status_code)
        for k, v in headers_dict.items():
            self.send_header(k, v)
        self.end_headers()

        self.wfile.write(data.encode())

    def __release_resources(self):
        """
        Releases server resources for a session termination caused by either:
        Close-Session or Cancel-Session
        """
        headers = {
            self.PACKET_TYPE: 'Ack',
            self.CONTENT_LENGTH: '0'
            }

        try:
            session_id = self.headers.get(self.SESSION_ID, None).lower()
            headers[self.SESSION_ID] = session_id
            self.log_message("Closing BITS-Session-Id: %s", session_id)

            self.sessions[session_id].close()
            self.sessions.pop(session_id, None)

            status_code = HTTPStatus.OK

        except AttributeError:
            self.__send_response(headers, status_code = HTTPStatus.BAD_REQUEST)
            return

        except Exception as e:
            print(e)
            raise ServerInternalError(e)

        self.__send_response(headers, status_code = status_code)

    def _handle_fragment(self):
        """
        Handles a new Fragment packet from the client, adding it to the relevant upload session
        """
        headers = {
            self.PACKET_TYPE: 'Ack',
            self.CONTENT_LENGTH: '0'
            }

        try:
            # obtain client headers
            session_id = self.headers.get(self.SESSION_ID, None).lower()
            content_length = int(self.headers.get(self.CONTENT_LENGTH, None))
            content_range = self.headers.get(self.CONTENT_RANGE, None).split(" ")[-1]
            # set response headers's session id
            headers[self.SESSION_ID] = session_id
            # normalize fragment details
            crange, total_length = content_range.split("/")
            total_length = int(total_length)
            range_start, range_end = [int(num) for num in crange.split("-")]

        except (AttributeError, IndexError):
            self.__send_response(status_code = HTTPStatus.BAD_REQUEST)
            return

        data = self.rfile.read(content_length)

        try:
            self.sessions[session_id].add_fragment(total_length, range_start, range_end, data)
            headers['BITS-Received-Content-Range'] = range_end + 1

        except InvalidFragment as e:
            headers[self.ERROR_CODE] = HResult.ZERO
            headers[self.ERROR_CONTEXT] = HResult.BG_ERROR_CONTEXT_REMOTE_FILE
            status_code = HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE
            self.log_message("ERROR processing new fragment (BITS-Session-Id: %s)." + \
                "New fragment range (%d) is not contiguous with last received (%d). context:%s, code:%s, exception:%s",
                session_id,
                e.new_range_start,
                e.last_range_end,
                headers[self.ERROR_CONTEXT],
                headers[self.ERROR_CODE],
                repr(e))

        except FragmentTooLarge as e:
            headers[self.ERROR_CODE] = HResult.BG_E_TOO_LARGE
            headers[self.ERROR_CONTEXT] = HResult.BG_ERROR_CONTEXT_REMOTE_FILE
            status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            self.log_message("ERROR processing new fragment (BITS-Session-Id: %s)." + \
                "New fragment size (%d) exceeds server limit (%d). context:%s, code:%s, exception:%s",
                session_id,
                e.fragment_size,
                BITSRequestHandler.fragment_size_limit,
                headers[self.ERROR_CONTEXT],
                headers[self.ERROR_CODE],
                repr(e))

        except Exception as e:
            print(e)
            raise ServerInternalError(e)

        status_code = HTTPStatus.OK
        self.__send_response(headers, status_code = status_code)

    def _handle_ping(self):
        """
        Handles Ping packet from client
        """
        self.log_message("{} RECEIVED".format("PING"))
        headers = {
            self.PACKET_TYPE: 'Ack',
            self.ERROR_CODE : '1',
            self.ERROR_CONTEXT: '',
            self.CONTENT_LENGTH: '0'
            }
        self.__send_response(headers, status_code = HTTPStatus.OK)

    def __get_current_session_id(self):
        return str(hash((self.connection.getpeername()[0], self.path)))

    def _handle_cancel_session(self):
        self.log_message("{} RECEIVED".format("CANCEL-SESSION"))
        return self.__release_resources()

    def _handle_close_session(self):
        self.log_message("{} RECEIVED".format("CLOSE-SESSION"))
        return self.__release_resources()

    def _handle_create_session(self):
        """
        Handles Create-Session packet from client. Creates the UploadSession.
        The unique ID that identifies a session in this server is a hash of the client's address and requested path.
        """
        self.log_message("{} RECEIVED".format("CREATE-SESSION"))

        headers = {
            self.PACKET_TYPE: 'Ack',
            self.CONTENT_LENGTH: '0'
            }

        if not getattr(self, "sessions", False):
            self.sessions = dict()
        try:
            # check if server's protocol version is supported in client
            client_supported_protocols = \
                self.headers.get(self.SUPPORTED_PROTOCOLS, None).lower().split(" ")
            protocols_intersection = set(client_supported_protocols).intersection(
                BITSRequestHandler.supported_protocols)

            # case mutual supported protocol is found
            if protocols_intersection:
                headers[self.PROTOCOL] = list(protocols_intersection)[0]
                requested_path = self.path[1:] if self.path.startswith("/") else self.path
                
                # check for directory traversal
                if '..' in requested_path:
                    raise UploadAccessDenied()
                
                absolute_file_path = os.path.join(BITSRequestHandler.base_dir, requested_path)

                session_id = self.__get_current_session_id()
                self.log_message("Creating BITS-Session-Id: {}".format(session_id))
                if session_id not in self.sessions:
                    self.sessions[session_id] = BITSUploadSession(absolute_file_path, BITSRequestHandler.fragment_size_limit)

                headers[self.SESSION_ID] = session_id
                status_code = self.sessions[session_id].get_last_status_code()
                if status_code == HTTPStatus.FORBIDDEN:
                    raise UploadAccessDenied()
            # case no mutual supported protocol is found
            else:
                raise ClientProtocolNotSupported(client_supported_protocols)

        except AttributeError:
            self.__send_response(headers, status_code = HTTPStatus.BAD_REQUEST)
            return

        except ClientProtocolNotSupported as e:
            status_code = HTTPStatus.BAD_REQUEST
            headers[self.ERROR_CODE] = HResult.E_INVALIDARG
            headers[self.ERROR_CONTEXT] = HResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.log_message("ERROR creating new session - protocol mismatch (%s). context:%s, code:%s, exception:%s",
                e.requested_protocols,
                headers[self.ERROR_CONTEXT],
                headers[self.ERROR_CODE],
                repr(e))

        except UploadAccessDenied as e:
            headers[self.ERROR_CODE] = HResult.E_ACCESSDENIED
            headers[self.ERROR_CONTEXT] = HResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.log_message("ERROR creating new session - Access Denied. context:%s, code:%s, exception:%s",
                headers[self.ERROR_CONTEXT],
                headers[self.ERROR_CODE],
                repr(e))

        except Exception as e:
            raise ServerInternalError(e)

        if status_code == HTTPStatus.OK or status_code == HTTPStatus.CREATED:
            headers[self.ACCEPT_ENCODING] = 'identity'

        self.__send_response(headers, status_code = status_code)

    def do_BITS_POST(self):
        headers = {}
        bits_packet_type = self.headers.get(self.PACKET_TYPE).lower()
        try:
            do_function = getattr(self, "_handle_{}".format(bits_packet_type.replace("-", "_")))
            try:
                do_function()
                return

            except ServerInternalError as e:
                status_code = HTTPStatus.INTERNAL_SERVER_ERROR
                headers[self.ERROR_CODE] = HResult.ERROR_CODE_GENERIC

        except AttributeError as e:
            # case an Unknown BITS-Packet-Type value was received by the server
            status_code = HTTPStatus.BAD_REQUEST
            headers[self.ERROR_CODE] = HResult.E_INVALIDARG

            headers[self.ERROR_CONTEXT] = HResult.BG_ERROR_CONTEXT_REMOTE_FILE
            self.log_message("Internal BITS Server Error. context:%s, code:%s, exception:%s",
                headers[self.ERROR_CONTEXT],
                headers[self.ERROR_CODE],
                e)

            self.__send_response(headers, status_code = status_code)


def run(server_class=HTTPServer, handler_class=BITSRequestHandler, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Starting BITS server...')
    httpd.serve_forever()


if __name__ == "__main__":
    import sys

    # log to file
    buffer = 1
    sys.stderr = open('bitsserver.log', 'w', buffer)

    if len(sys.argv) == 2:
        run(port=int(sys.argv[1]))
    elif len(sys.argv) < 2:
        print('usage: python3 -m bitsserver <port>')
    else:
        run()
