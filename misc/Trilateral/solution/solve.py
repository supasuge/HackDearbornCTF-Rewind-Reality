from pwn import *
import re
import math
import numpy as np

# Trilateration calculation using three spheres in ECEF
def trilaterate_ecef(P1, P2, P3, r1, r2, r3):
    P1 = np.array(P1)
    P2 = np.array(P2)
    P3 = np.array(P3)

    ex = P2 - P1
    ex_norm = np.linalg.norm(ex)
    if ex_norm == 0:
        return None
    ex = ex / ex_norm

    P3P1 = P3 - P1
    i = np.dot(ex, P3P1)
    ey = P3P1 - i * ex
    ey_norm = np.linalg.norm(ey)
    if ey_norm == 0:
        return None
    ey = ey / ey_norm

    ez = np.cross(ex, ey)

    d = np.linalg.norm(P2 - P1)
    j = np.dot(ey, P3P1)

    # Check for coplanar points
    if j == 0:
        return None

    x = (r1**2 - r2**2 + d**2) / (2 * d)
    y = (r1**2 - r3**2 + i**2 + j**2) / (2 * j) - (i / j) * x
    z_sq = r1**2 - x**2 - y**2

    if z_sq < 0:
        return None

    z = math.sqrt(z_sq)

    result1 = P1 + x * ex + y * ey + z * ez
    result2 = P1 + x * ex + y * ey - z * ez

    # Choose the result closest to P1
    dist1 = np.linalg.norm(result1 - P1)
    dist2 = np.linalg.norm(result2 - P1)

    if dist1 < dist2:
        return result1
    else:
        return result2

# Convert lat, lon to ECEF coordinates
def latlon_to_ecef(lat, lon):
    R = 6371.0  # Earth's radius in km
    lat_rad = math.radians(lat)
    lon_rad = math.radians(lon)
    x = R * math.cos(lat_rad) * math.cos(lon_rad)
    y = R * math.cos(lat_rad) * math.sin(lon_rad)
    z = R * math.sin(lat_rad)
    return [x, y, z]

# Convert ECEF coordinates back to lat, lon
def ecef_to_latlon(x, y, z):
    R = math.sqrt(x**2 + y**2 + z**2)
    lat_rad = math.asin(z / R)
    lon_rad = math.atan2(y, x)
    lat = math.degrees(lat_rad)
    lon = math.degrees(lon_rad)
    return lat, lon

def trilaterate(lat1, lon1, r1, lat2, lon2, r2, lat3, lon3, r3):
    P1 = latlon_to_ecef(lat1, lon1)
    P2 = latlon_to_ecef(lat2, lon2)
    P3 = latlon_to_ecef(lat3, lon3)

    result = trilaterate_ecef(P1, P2, P3, r1, r2, r3)
    if result is None:
        return None, None
    lat, lon = ecef_to_latlon(result[0], result[1], result[2])
    return round(lat, 6), round(lon, 6)

def main():
    # Configure pwntools context
    context.log_level = 'info'  # Set to 'debug' for more verbose output

    # Replace 'localhost' and 1337 with actual server IP and port if different
    HOST = 'localhost'
    PORT = 1337

    # Connect to the server
    try:
        io = remote(HOST, PORT)
    except Exception as e:
        print(f"Failed to connect to {HOST}:{PORT}: {e}")
        return

    # Receive the banner and challenge info
    try:
        # Assuming the banner ends with "Good luck, Operator!"
        banner = io.recvuntil(b"Good luck, Operator!", timeout=10)
        print(banner.decode())
    except EOFError:
        print("Connection closed by server during banner reception.")
        io.close()
        return
    except Exception as e:
        print(f"Error receiving banner: {e}")
        io.close()
        return

    # Iterate through five problems
    for problem_num in range(1, 6):
        try:
            # Receive problem header
            problem_header = io.recvuntil(f"Problem {problem_num}:".encode(), timeout=10)
            print(problem_header.decode())
        except EOFError:
            print("Connection closed by server during problem header reception.")
            io.close()
            return
        except Exception as e:
            print(f"Error receiving problem header: {e}")
            io.close()
            return

        try:
            # Receive base station details up to "Provide the (latitude, longitude)"
            base_info = io.recvuntil(b"Provide the (latitude, longitude)", timeout=10)
            print(base_info.decode())
        except EOFError:
            print("Connection closed by server during base station details reception.")
            io.close()
            return
        except Exception as e:
            print(f"Error receiving base station details: {e}")
            io.close()
            return

        # Extract base station details using regex
        # Pattern: BaseStationName: Location = (lat, lon), Distance = r.rr km
        pattern = r"(\w+): Location = \(([-\d\.]+), ([-\d\.]+)\), Distance = ([\d\.]+) km"
        towers = re.findall(pattern, base_info.decode())

        if len(towers) != 3:
            print("Failed to parse base station information.")
            # Optionally, send an incorrect answer to prompt server to exit
            io.sendline(b"0.00,0.00")
            io.close()
            return

        # Parse tower data
        tower1 = towers[0]
        tower2 = towers[1]
        tower3 = towers[2]

        name1, lat1, lon1, r1 = tower1
        name2, lat2, lon2, r2 = tower2
        name3, lat3, lon3, r3 = tower3

        lat1, lon1, r1 = float(lat1), float(lon1), float(r1)
        lat2, lon2, r2 = float(lat2), float(lon2), float(r2)
        lat3, lon3, r3 = float(lat3), float(lon3), float(r3)

        print(f"Parsed Towers:\n  {name1}: ({lat1}, {lon1}), Distance: {r1} km\n  {name2}: ({lat2}, {lon2}), Distance: {r2} km\n  {name3}: ({lat3}, {lon3}), Distance: {r3} km")

        # Perform trilateration to find phone location
        phone_lat, phone_lon = trilaterate(lat1, lon1, r1, lat2, lon2, r2, lat3, lon3, r3)

        if phone_lat is None or phone_lon is None:
            print("Trilateration failed due to invalid input.")
            # Optionally, send an incorrect answer to prompt server to exit
            io.sendline(b"0.00,0.00")
            io.close()
            return

        # Prepare answer
        answer = f"{phone_lat},{phone_lon}\n"
        print(f"Sending Answer for Problem {problem_num}: {answer.strip()}")

        # Send the answer as bytes
        io.sendline(answer.encode())

        # Receive validation response
        try:
            # Assuming the response is a single line
            response = io.recvline(timeout=10)
            if not response:
                print("No response received. Connection might be closed by the server.")
                io.close()
                return
            response_decoded = response.decode().strip()
            print(response_decoded)
        except EOFError:
            print("Connection closed by server after sending the answer.")
            io.close()
            return
        except Exception as e:
            print(f"Error receiving validation response: {e}")
            io.close()
            return

        if "Correct!" in response_decoded:
            continue  # Proceed to next problem
        elif "Incorrect" in response_decoded or "Exiting" in response_decoded:
            # If incorrect, attempt to read any further messages
            try:
                final_message = io.recvall(timeout=5).decode()
                print(final_message)
            except EOFError:
                pass
            io.close()
            return
        elif "flag" in response_decoded.lower():
            print(response_decoded)
            io.close()
            return

    # After all problems are solved correctly, receive the flag
    try:
        final_message = io.recvall(timeout=10).decode()
        print(final_message)
    except EOFError:
        print("Connection closed by server after all problems.")
    except Exception as e:
        print(f"Error receiving final message: {e}")

    io.close()

if __name__ == "__main__":
    main()
