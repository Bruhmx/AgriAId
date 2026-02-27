import tensorflow as tf
import numpy as np
from PIL import Image
import warnings
import os
import glob
warnings.filterwarnings('ignore')

# Load models (with error handling)
try:
    crop_model = tf.keras.models.load_model("models/crop_model_final.keras")
    corn_model = tf.keras.models.load_model("models/corn_model_final.keras")
    rice_model = tf.keras.models.load_model("models/rice_model_final.keras")
    print("✓ Models loaded successfully")
except Exception as e:
    print(f"✗ Error loading models: {e}")
    # Create dummy models for development
    crop_model = None
    corn_model = None
    rice_model = None

# Class mappings with display names
CROP_CLASSES = ["corn", "rice"]
CROP_DISPLAY_NAMES = {
    "corn": "Corn (Maize)",
    "rice": "Rice"
}

CORN_CLASSES = ["Common_Rust", "gls", "healthy", "nclb"]
CORN_DISPLAY_NAMES = {
    "Common_Rust": "Common Rust",
    "gls": "Gray Leaf Spot",
    "healthy": "Healthy",
    "nclb": "Northern Corn Leaf Blight"
}

RICE_CLASSES = ["blast", "blight", "brownspot", "healthy", "tungro"]
RICE_DISPLAY_NAMES = {
    "blast": "Rice Blast",
    "blight": "Bacterial Leaf Blight",
    "brownspot": "Brown Spot",
    "healthy": "Healthy",
    "tungro": "Tungro Virus"
}


def preprocess_image(img_path, img_size=(224, 224)):
    """Preprocess image for model prediction"""
    try:
        img = Image.open(img_path)
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        # Resize and normalize
        img = img.resize(img_size)
        img_array = np.array(img) / 255.0
        return np.expand_dims(img_array, axis=0)
    except Exception as e:
        print(f"Error preprocessing image: {e}")
        # Return dummy array for development
        return np.zeros((1, 224, 224, 3))


def predict_crop(img_path):
    """Predict crop type from image"""
    if crop_model is None:
        # Development fallback
        return "corn", 0.85

    img = preprocess_image(img_path)
    predictions = crop_model.predict(img, verbose=0)[0]
    pred_idx = np.argmax(predictions)
    crop = CROP_CLASSES[pred_idx]
    confidence = float(predictions[pred_idx])
    return crop, confidence


def predict_disease(img_path, crop):
    """Predict disease based on crop type"""
    img = preprocess_image(img_path)

    if crop == "corn":
        if corn_model is None:
            # Development fallback
            return [("Common_Rust", 0.7), ("gls", 0.2), ("healthy", 0.1)]

        predictions = corn_model.predict(img, verbose=0)[0]
        classes = CORN_CLASSES
    else:  # rice
        if rice_model is None:
            # Development fallback
            return [("blast", 0.6), ("blight", 0.3), ("healthy", 0.1)]

        predictions = rice_model.predict(img, verbose=0)[0]
        classes = RICE_CLASSES

    # Create list of (class, confidence) pairs
    results = list(zip(classes, predictions))
    # Sort by confidence (descending)
    results.sort(key=lambda x: x[1], reverse=True)

    return results[:3]  # Return top 3 predictions


def get_crop_display_name(crop_code):
    """Get user-friendly crop name"""
    return CROP_DISPLAY_NAMES.get(crop_code, crop_code.title())


def get_disease_display_name(disease_code):
    """Get user-friendly disease name"""
    if disease_code in CORN_DISPLAY_NAMES:
        return CORN_DISPLAY_NAMES.get(disease_code, disease_code.title())
    else:
        return RICE_DISPLAY_NAMES.get(disease_code, disease_code.title())


def get_sample_images(disease_code, crop):
    """Return local sample image paths for the diagnosed disease"""
    # Clean disease code for folder names (replace spaces with underscores)
    clean_disease_code = disease_code.replace(' ', '_')

    # Define the sample images directory
    base_dir = 'static/samples'
    sample_dir = os.path.join(base_dir, crop, clean_disease_code)

    # Check if directory exists
    if os.path.exists(sample_dir):
        # Get all image files from the directory
        image_extensions = ['*.jpg', '*.jpeg', '*.png', '*.gif', '*.webp']
        image_files = []

        for ext in image_extensions:
            image_files.extend(glob.glob(os.path.join(sample_dir, ext)))

        # Sort files to maintain consistency
        image_files.sort()

        # Convert to URL paths (relative to static folder)
        sample_urls = []
        for img_path in image_files[:4]:  # Get max 4 images
            # Convert to URL path (relative from static folder)
            # Example: static/samples/corn/Common_Rust/sample1.jpg -> /static/samples/corn/Common_Rust/sample1.jpg
            rel_path = img_path.replace('\\', '/')  # For Windows compatibility
            sample_urls.append('/' + rel_path)

        # Return the URLs if we found images
        if sample_urls:
            return sample_urls

    # Return default/fallback images if no samples found
    return get_default_sample_images(crop, disease_code)


def get_default_sample_images(crop, disease_code):
    """Return default sample images when no specific images are found"""
    # You can create some generic sample images for each crop
    generic_images = {
        'corn': [
            '/static/samples/default/corn_sample1.jpg',
            '/static/samples/default/corn_sample2.jpg',
            '/static/samples/default/corn_sample3.jpg',
            '/static/samples/default/corn_sample4.jpg'
        ],
        'rice': [
            '/static/samples/default/rice_sample1.jpg',
            '/static/samples/default/rice_sample2.jpg',
            '/static/samples/default/rice_sample3.jpg',
            '/static/samples/default/rice_sample4.jpg'
        ]
    }

    # Create the default directory if it doesn't exist
    default_dir = 'static/samples/default'
    os.makedirs(default_dir, exist_ok=True)

    # Check if default images exist, if not provide placeholder text
    if crop in generic_images:
        # Check if at least one image exists
        if os.path.exists(generic_images[crop][0].lstrip('/')):
            return generic_images[crop]

    # Ultimate fallback - placeholder message
    return []

def get_model_info():
    """Get information about loaded models"""
    info = {
        'crop_model': 'Loaded' if crop_model else 'Not loaded',
        'corn_model': 'Loaded' if corn_model else 'Not loaded',
        'rice_model': 'Loaded' if rice_model else 'Not loaded',
    }
    return info
