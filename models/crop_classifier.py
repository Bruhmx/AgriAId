import numpy as np
from utils.config import Config


class CropClassifier:
    def __init__(self, model_loader):
        self.model = model_loader.crop_model
        self.classes = Config.CROP_CLASSES

    def predict_crop(self, processed_image):
        """Predict if image is corn or rice"""
        predictions = self.model.predict(processed_image, verbose=0)
        pred_idx = np.argmax(predictions[0])
        confidence = float(predictions[0][pred_idx])
        crop_type = self.classes[pred_idx]

        return {
            'crop': crop_type,
            'confidence': confidence,
            'all_predictions': {
                self.classes[i]: float(predictions[0][i])
                for i in range(len(self.classes))
            }
        }