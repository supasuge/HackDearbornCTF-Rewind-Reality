import socketserver
import threading
import random
import math
import numpy as np
import logging

def haversine_distance(lat1, lon1, lat2, lon2, unit='km'):
    # Earth radius in kilometers and miles
    R_km = 6371.0
    R_mi = 3958.8

    # Convert latitude and longitude from degrees to radians
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    # Haversine formula
    a = math.sin(delta_phi / 2.0)**2 + \
        math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    # Calculate distance
    if unit == 'km':
        distance = R_km * c
    elif unit == 'mi':
        distance = R_mi * c
    else:
        raise ValueError("Invalid unit. Use 'km' for kilometers or 'mi' for miles.")

    return round(distance, 2)

# Configure logging
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Fixed ASCII Art Banner
BANNER = """

------------------------------------------------------------------------
 ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║██║   ██║██╔██╗ ██║
██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                        
███████╗███╗   ██╗██████╗  ██████╗  █████╗ ███╗   ███╗███████╗          
██╔════╝████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝          
█████╗  ██╔██╗ ██║██║  ██║██║  ███╗███████║██╔████╔██║█████╗            
██╔══╝  ██║╚██╗██║██║  ██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝            
███████╗██║ ╚████║██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗          
╚══════╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝          
------------------------------------------------------------------------
"""

# Read flag from file
try:
    with open("flag.txt", "r") as f:
        FLAG = f.read().strip()
except FileNotFoundError:
    FLAG = "CTF{Flag_Not_Found}"

# Challenge Information with Perfect Square Borders
CHALLENGE_INFO = """
[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]
[+] It is the year 2006, and you are an elite intelligence operative working with the FBI to track down an        [+]
[+] Advanced Persistent Threat (APT) individual who was previously believed to be operating abroad. Recent        [+]
[+] intelligence indicates that this individual is temporarily residing in the United States.                     [+]
[+] The APT expert is highly intelligent and backed by substantial resources, making him a formidable target.     [+]
[+] To locate him, a Stingray (IMSI Catcher) device has been deployed near his known residence in Miami. Over the [+]
[+] past three days, he has been frequently on the move, conducting cash pickups and drop-offs across different   [+]
[+] areas of the country. Each time he makes a transaction, he activates his mobile device, allowing us to        [+]
[+] triangulate his location based on signal data from multiple base stations.                                    [+]
[+]                                                                                                               [+]
[+] Your task is to solve five trilateration problems to help pinpoint his exact locations during these operations[+]
[+]                                                                                                               [+]
[+] Provide the exact (latitude, longitude) coordinates for each location to receive the flag.                    [+]
[+]                                                                                                               [+]
[+] Good luck, Operator!                                                                                          [+]
[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]
"""

ADDITIONAL_BASE_STATIONS = [
    {'name': 'BaseStationNY', 'lat': 40.71427, 'lon': -74.00597},    # New York
    {'name': 'BaseStationLA', 'lat': 34.05223, 'lon': -118.24368},   # Los Angeles
    {'name': 'BaseStationCH', 'lat': 41.87811, 'lon': -87.6298},     # Chicago
    {'name': 'BaseStationHO', 'lat': 29.76043, 'lon': -95.3698},     # Houston
    {'name': 'BaseStationPE', 'lat': 33.44838, 'lon': -112.07404},   # Phoenix
    {'name': 'BaseStationPI', 'lat': 39.95258, 'lon': -75.16522},    # Philadelphia
    {'name': 'BaseStationSA', 'lat': 29.42412, 'lon': -98.49363},    # San Antonio
    {'name': 'BaseStationSD', 'lat': 32.71571, 'lon': -117.16472},   # San Diego
    {'name': 'BaseStationD', 'lat': 32.77627, 'lon': -96.7970},      # Dallas
]

# Function to generate trilateration problem with realistic coordinates
def generate_problem():
    # Fixed Stingray device in Miami
    miami_lat, miami_lon = 25.733414, -80.241092

    # Randomly select two distinct base stations from the additional list
    base_stations = random.sample(ADDITIONAL_BASE_STATIONS, 2)

    # Combine with StingrayMiami
    selected_stations = [
        {'name': 'StingrayMiami', 'lat': miami_lat, 'lon': miami_lon},
        base_stations[0],
        base_stations[1]
    ]

    # Randomly choose a phone location within the USA boundaries
    # Latitude: 24.396308 to 49.384358
    # Longitude: -124.848974 to -66.885444
    while True:
        phone_lat = round(random.uniform(24.396308, 49.384358), 6)
        phone_lon = round(random.uniform(-124.848974, -66.885444), 6)
        # Ensure phone location does not coincide with any base station and is at least 1 km away
        min_distance = min(
            haversine_distance(phone_lat, phone_lon, station['lat'], station['lon'], unit='km')
            for station in selected_stations
        )
        if min_distance >= 1.0:
            logging.info(f"Generated phone location: ({phone_lat}, {phone_lon})")
            break
        else:
            logging.info(f"Rejected phone location: ({phone_lat}, {phone_lon}) - Too close to a base station.")

    # Calculate distances from each base station to the phone location
    distances = []
    for station in selected_stations:
        distance = haversine_distance(station['lat'], station['lon'], phone_lat, phone_lon, unit='km')
        distances.append({'name': station['name'], 'distance': distance})

    return {
        'towers': selected_stations,
        'phone_location': {'lat': phone_lat, 'lon': phone_lon},
        'distances': distances
    }

# Handler class using socketserver
class TrilaterationHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            # Send Banner
            self.wfile.write(BANNER.encode())
            self.wfile.flush()

            # Send Challenge Information
            self.wfile.write(CHALLENGE_INFO.encode())
            self.wfile.flush()

            # Initialize correct answer count
            correct_answers = 0

            # Serve five trilateration problems
            for problem_num in range(1, 6):
                problem = generate_problem()
                towers = problem['towers']
                phone_location = problem['phone_location']
                distances = problem['distances']

                # Prepare problem text
                problem_text = f"\nProblem {problem_num}:\n"
                problem_text += "Three base stations have detected a mobile device. Here are the base station details:\n"
                for station in distances:
                    # Fetch the station's lat and lon
                    station_info = next((s for s in towers if s['name'] == station['name']), None)
                    if station_info:
                        problem_text += f"  {station['name']}: Location = ({station_info['lat']:.6f}, {station_info['lon']:.6f}), Distance = {station['distance']:.2f} km\n"
                problem_text += "Provide the (latitude, longitude) coordinates of the mobile device's location.\n"
                problem_text += "Format: lat,lon (e.g., 12.34,-56.78)\n"
                self.wfile.write(problem_text.encode())
                self.wfile.flush()

                # Prompt for answer
                self.wfile.write(f"\nEnter your answer for Problem {problem_num}: ".encode())
                self.wfile.flush()

                # Receive answer
                answer = self.rfile.readline().decode().strip()
                if not answer:
                    self.wfile.write("No input received. Exiting.\n".encode())
                    self.wfile.flush()
                    break

                try:
                    user_lat, user_lon = map(float, answer.split(','))
                except:
                    self.wfile.write("Invalid format. Use lat,lon with decimal points.\n".encode())
                    self.wfile.write("Exiting due to invalid input.\n".encode())
                    self.wfile.flush()
                    break

                # Get expected location
                expected_lat = phone_location['lat']
                expected_lon = phone_location['lon']

                # Calculate distance between user answer and actual phone location
                error_distance = haversine_distance(user_lat, user_lon, expected_lat, expected_lon, unit='km')

                # Allow a margin of error (e.g., within 1 km)
                if error_distance <= 1.0:
                    correct_answers += 1
                    self.wfile.write("Correct!\n".encode())
                    self.wfile.flush()
                else:
                    self.wfile.write(f"Incorrect. The correct location was ({expected_lat:.6f}, {expected_lon:.6f}).\n".encode())
                    self.wfile.write("You've failed to locate the device accurately. Exiting.\n".encode())
                    self.wfile.flush()
                    return  # Exit upon incorrect answer

            # After five correct answers, send the flag
            if correct_answers == 5:
                self.wfile.write(f"\nCongratulations! Here is your flag: {FLAG}\n".encode())
                self.wfile.flush()
            else:
                self.wfile.write("\nSome answers were incorrect. Better luck next time!\n".encode())
                self.wfile.flush()

        except Exception as e:
            logging.error(f"Error handling client {self.client_address}: {e}")

# Threaded TCP Server
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def start_server(host='0.0.0.0', port=1337):
    server = ThreadedTCPServer((host, port), TrilaterationHandler)
    server.allow_reuse_address = True
    print(f"Trilateration Challenge Server running on {host}:{port}")
    logging.info(f"Trilateration Challenge Server started on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
        logging.info("Trilateration Challenge Server shutting down.")
    finally:
        server.server_close()

if __name__ == "__main__":
    start_server()
