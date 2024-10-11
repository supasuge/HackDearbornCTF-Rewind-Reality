from PIL import Image, ImageDraw, ImageFont

def overlay_ascii_art(frame_path, ascii_art_path, output_path, position=(100, 50), scale_factor=0.5):
    # Load the frame image
    frame = Image.open(frame_path).convert("RGBA")

    # Load the ASCII art
    with open(ascii_art_path, 'r') as file:
        ascii_art = file.read()

    # Create a drawing context
    draw = ImageDraw.Draw(frame)

    # Set a font size and calculate the new font size based on the scale factor
    base_font_size = 12 # Original font size
    font_size = int(base_font_size * scale_factor)
    font = ImageFont.load_default()  # Use default font or specify a .ttf font

    # Create a new image for the text with transparency
    text_image = Image.new('RGBA', frame.size, (255, 255, 255, 0))  # Transparent background
    text_draw = ImageDraw.Draw(text_image)

    # Draw the ASCII art onto the transparent image with desired transparency
    text_draw.text(position, ascii_art, fill=(255, 255, 255, 128), font=font)

    # Combine the frame and the text image
    combined = Image.alpha_composite(frame, text_image)

    # Save the modified frame as a PNG to preserve transparency
    combined.save(output_path, "PNG")

# Example usage
frame_path = 'frame_014.png'          # Path to your frame image
ascii_art_path = 'ascii.txt'          # Path to your ASCII art text file
output_path = 'modified_frame_001.png'  # Path to save the modified frame

overlay_ascii_art(frame_path, ascii_art_path, output_path, scale_factor=0.9)
