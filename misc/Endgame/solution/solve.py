from pwn import *
import re
import math
import numpy as np
from scipy.optimize import least_squares

# Haversine distance function
def haversine_distance(lat1, lon1, lat2, lon2):
    # Earth radius in kilometers
    R = 6371.0
    # Convert latitude and longitude from degrees to radians
    phi1 = np.radians(lat1)
    phi2 = np.radians(lat2)
    delta_phi = np.radians(lat2 - lat1)
    delta_lambda = np.radians(lon2 - lon1)
    # Haversine formula
    a = np.sin(delta_phi / 2.0)**2 + \
        np.cos(phi1) * np.cos(phi2) * np.sin(delta_lambda / 2.0)**2
    c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))
    # Calculate distance
    distance = R * c
    return distance

# Residuals function for least squares optimization
def residuals(x, towers):
    lon, lat = x  # Swap order: x[0] is longitude, x[1] is latitude
    res = []
    for tower in towers:
        tower_lat, tower_lon, dist = tower
        calc_dist = haversine_distance(lat, lon, tower_lat, tower_lon)
        res.append(calc_dist - dist)
    return res

# Trilateration function using least squares optimization with improvements
def trilaterate(towers):
    # Define bounds for latitude and longitude (USA boundaries)
    lat_bounds = (24.396308, 49.384358)
    lon_bounds = (-124.848974, -66.885444)

    # Prepare initial guesses (average position and tower positions)
    initial_guesses = [
        (sum(t[1] for t in towers) / len(towers), sum(t[0] for t in towers) / len(towers))
    ] + [(t[1], t[0]) for t in towers]

    best_result = None
    best_cost = float('inf')

    for guess in initial_guesses:
        result = least_squares(
            residuals,
            guess,
            args=(towers,),
            bounds=([lon_bounds[0], lat_bounds[0]], [lon_bounds[1], lat_bounds[1]]),
            max_nfev=2000,
            ftol=1e-12,
            xtol=1e-12,
            verbose=0
        )

        if result.success:
            if result.cost < best_cost:
                best_result = result
                best_cost = result.cost

    if best_result is None:
        print("Optimization failed.")
        return None, None

    lon, lat = best_result.x  # Extract longitude and latitude
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
            # Receive up to the prompt
            problem_data = io.recvuntil(f"Enter your answer for Problem {problem_num}: ".encode(), timeout=10)
            print(problem_data.decode())
        except EOFError:
            print("Connection closed by server during problem reception.")
            io.close()
            return
        except Exception as e:
            print(f"Error receiving problem data: {e}")
            io.close()
            return

        # Extract base station details using regex
        # Pattern: BaseStationName: Location = (lat, lon), Distance = r.rr km
        pattern = r"(\w+): Location = \(([-\d\.]+), ([-\d\.]+)\), Distance = ([\d\.]+) km"
        towers_data = re.findall(pattern, problem_data.decode())

        if len(towers_data) != 3:
            print("Failed to parse base station information.")
            # Optionally, send an incorrect answer to prompt server to exit
            io.sendline(b"0.00,0.00")
            io.close()
            return

        # Parse tower data
        towers = []
        for tower in towers_data:
            name, lat_str, lon_str, dist_str = tower
            lat, lon, dist = float(lat_str), float(lon_str), float(dist_str)
            towers.append((lat, lon, dist))

        print("Parsed Towers:")
        for idx, (lat, lon, dist) in enumerate(towers):
            print(f"  Tower {idx+1}: ({lat}, {lon}), Distance: {dist} km")

        # Perform trilateration to find phone location
        phone_lat, phone_lon = trilaterate(towers)

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
            # Receive until you get "Correct!" or "Incorrect"
            response = io.recvuntil([b"Correct!", b"Incorrect"], timeout=10)
            response_decoded = response.decode()
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
