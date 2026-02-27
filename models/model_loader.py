import tensorflow as tf
import numpy as np
from tensorflow import keras
from utils.config import Config


class ModelLoader:
    def __init__(self):
        self.crop_model = None
        self.rice_model = None
        self.corn_model = None
        self.loaded = False

    def load_models(self):
        """Load your trained .keras models"""
        try:
            print("🔍 Loading models...")

            # Load crop model
            print(f"   Loading crop model: {Config.CROP_MODEL_PATH}")
            self.crop_model = keras.models.load_model(Config.CROP_MODEL_PATH)
            print(f"   ✓ Crop model loaded (classes: {Config.CROP_CLASSES})")

            # Load rice disease model
            print(f"   Loading rice model: {Config.RICE_DISEASE_MODEL_PATH}")
            self.rice_model = keras.models.load_model(Config.RICE_DISEASE_MODEL_PATH)
            print(f"   ✓ Rice model loaded (classes: {Config.RICE_DISEASE_CLASSES})")

            # Load corn disease model
            print(f"   Loading corn model: {Config.CORN_DISEASE_MODEL_PATH}")
            self.corn_model = keras.models.load_model(Config.CORN_DISEASE_MODEL_PATH)
            print(f"   ✓ Corn model loaded (classes: {Config.CORN_DISEASE_CLASSES})")

            self.loaded = True
            print("✅ All models loaded successfully!")
            return True

        except Exception as e:
            print(f"❌ Error loading models: {e}")
            print(f"\nError details: {type(e).__name__}")
            return False

    def get_model_for_crop(self, crop_type):
        """Get disease model for specific crop"""
        if crop_type == 'rice':
            return self.rice_model, Config.RICE_DISEASE_CLASSES
        elif crop_type == 'corn':
            return self.corn_model, Config.CORN_DISEASE_CLASSES
        else:
            raise ValueError(f"Unknown crop: {crop_type}")


model_loader = ModelLoader()