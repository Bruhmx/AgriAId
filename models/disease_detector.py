import numpy as np
from utils.config import Config


class DiseaseDetector:
    def __init__(self, model_loader):
        self.model_loader = model_loader

    def detect_diseases(self, processed_image, crop_type):
        """Detect diseases for specific crop"""
        model, disease_classes = self.model_loader.get_model_for_crop(crop_type)

        predictions = model.predict(processed_image, verbose=0)
        pred_array = predictions[0]

        # Get top 3 predictions
        top_indices = np.argsort(pred_array)[::-1][:3]

        detected_diseases = []
        for idx in top_indices:
            disease_code = disease_classes[idx]
            confidence = float(pred_array[idx])

            detected_diseases.append({
                'code': disease_code,
                'name': Config.DISEASE_DISPLAY_NAMES.get(disease_code, disease_code),
                'confidence': confidence
            })

        return detected_diseases