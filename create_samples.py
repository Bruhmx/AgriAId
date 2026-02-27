# create_samples.py
import os
from PIL import Image, ImageDraw, ImageFont
import json


def create_sample_images():
    """Create sample image structure with placeholder images"""

    # Create base directory
    os.makedirs('static/samples', exist_ok=True)

    # Define diseases for each crop
    crops = {
        'corn': ['Common_Rust', 'gls', 'nclb', 'healthy'],
        'rice': ['blast', 'blight', 'brownspot', 'tungro', 'healthy']
    }

    # Colors for different diseases
    colors = {
        'Common_Rust': (165, 42, 42),  # Brown
        'gls': (128, 128, 128),  # Gray
        'nclb': (139, 69, 19),  # Saddle Brown
        'blast': (220, 20, 60),  # Crimson
        'blight': (30, 144, 255),  # Dodger Blue
        'brownspot': (160, 82, 45),  # Sienna
        'tungro': (255, 165, 0),  # Orange
        'healthy': (60, 179, 113)  # Medium Sea Green
    }

    for crop, diseases in crops.items():
        for disease in diseases:
            # Clean disease name for display
            display_disease = disease.replace('_', ' ').title()
            if disease == 'gls':
                display_disease = 'Gray Leaf Spot'
            elif disease == 'nclb':
                display_disease = 'Northern Corn Leaf Blight'
            elif disease == 'blight':
                display_disease = 'Bacterial Leaf Blight'

            # Create disease directory
            disease_dir = f'static/samples/{crop}/{disease}'
            os.makedirs(disease_dir, exist_ok=True)

            # Create 4 sample images for each disease
            for i in range(1, 5):
                img_path = f'{disease_dir}/sample{i}.jpg'

                # Create image with different colors for each disease
                color = colors.get(disease, (200, 220, 200))
                img = Image.new('RGB', (400, 300), color=color)
                draw = ImageDraw.Draw(img)

                # Add disease pattern (simple circles for lesions)
                if disease != 'healthy':
                    # Draw some "lesions" on the image
                    for _ in range(10 + i * 5):
                        x = np.random.randint(50, 350)
                        y = np.random.randint(50, 250)
                        size = np.random.randint(5, 20)
                        draw.ellipse([x, y, x + size, y + size],
                                     fill=(color[0] // 2, color[1] // 2, color[2] // 2))

                # Add text
                try:
                    font = ImageFont.truetype("arial.ttf", 16)
                except:
                    font = ImageFont.load_default()

                text = f"{crop.title()}\n{display_disease}\nSample {i}"
                draw.text((20, 120), text, fill=(255, 255, 255), font=font)

                # Add stage text
                stages = ['Early Stage', 'Moderate Stage', 'Advanced Stage', 'Severe Stage']
                draw.text((20, 180), stages[i - 1], fill=(255, 255, 255), font=font)

                # Save image
                img.save(img_path)
                print(f"Created: {img_path}")

    print("\n✓ Sample image structure created successfully!")
    print("Folder structure:")
    print("static/samples/")
    print("├── corn/")
    print("│   ├── Common_Rust/")
    print("│   ├── gls/")
    print("│   ├── nclb/")
    print("│   └── healthy/")
    print("└── rice/")
    print("    ├── blast/")
    print("    ├── blight/")
    print("    ├── brownspot/")
    print("    ├── tungro/")
    print("    └── healthy/")


if __name__ == "__main__":
    import numpy as np

    create_sample_images()