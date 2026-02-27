// AgriAID Application JavaScript with AI Integration
class AgriAID {
    constructor() {
        this.currentStep = 1;
        this.totalSteps = 4;
        this.selectedCrop = null;
        this.uploadedImage = null;
        this.selectedSymptoms = [];
        this.aiPrediction = null;
        this.questions = [];
        this.answers = {};
        this.diagnosisResult = null;
        this.apiBaseUrl = 'http://localhost:5000/api';

        this.initialize();
    }

    initialize() {
        this.setupEventListeners();
        this.updateUI();
        this.setupDragAndDrop();
        this.checkSystemStatus();
    }

    setupEventListeners() {
        // Navigation buttons
        document.getElementById('prevBtn').addEventListener('click', () => this.prevStep());
        document.getElementById('nextBtn').addEventListener('click', () => this.nextStep());

        // Image upload
        document.getElementById('uploadArea').addEventListener('click', () => {
            document.getElementById('imageInput').click();
        });

        document.getElementById('imageInput').addEventListener('change', (e) => this.handleImageUpload(e));

        // Custom symptom
        document.getElementById('addSymptomBtn').addEventListener('click', () => this.addCustomSymptom());
        document.getElementById('customSymptom').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.addCustomSymptom();
        });
    }

    async checkSystemStatus() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/health`);
            const data = await response.json();

            if (!data.models_loaded.crop_model || !data.models_loaded.rice_model || !data.models_loaded.corn_model) {
                this.showNotification('Some AI models are not loaded. System may not work correctly.', 'warning');
            } else {
                console.log('✅ All AI models are loaded and ready');
            }
        } catch (error) {
            console.error('Error checking system status:', error);
        }
    }

    async handleImageUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        if (!this.validateImageFile(file)) return;

        this.showLoading(true);

        try {
            const formData = new FormData();
            formData.append('image', file);

            const response = await fetch(`${this.apiBaseUrl}/upload`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error('Upload failed');

            const result = await response.json();

            if (result.success) {
                this.uploadedImage = result;
                this.aiPrediction = result.predictions;

                // Display image preview
                this.displayImagePreview(result.filename);

                // Move to next step (AI Analysis)
                setTimeout(() => {
                    this.nextStep();
                    // Display AI results
                    this.displayAIResults(result);
                }, 500);

                this.showNotification('Image uploaded and analyzed by AI!', 'success');
            } else {
                throw new Error(result.error || 'Upload failed');
            }
        } catch (error) {
            console.error('Upload error:', error);
            this.showNotification(error.message || 'Error uploading image', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    displayImagePreview(filename) {
        const previewContainer = document.getElementById('previewContainer');
        const imageUrl = `${this.apiBaseUrl.replace('/api', '')}/uploads/${filename}`;

        previewContainer.innerHTML = `
            <div class="image-preview">
                <img src="${imageUrl}" alt="Preview" class="preview-image" id="uploadedImage">
                <div class="image-info">
                    <p>Image uploaded successfully</p>
                    <p>AI analysis in progress...</p>
                </div>
            </div>
        `;
    }

    displayAIResults(result) {
        const analysisContainer = document.getElementById('aiAnalysisResults');

        if (!result.predictions || !result.predictions.crop) {
            analysisContainer.innerHTML = `
                <div class="ai-result error">
                    <h4>❌ AI Analysis Failed</h4>
                    <p>Could not analyze the image. Please try again.</p>
                </div>
            `;
            return;
        }

        const cropPred = result.predictions.crop;
        const diseasePred = result.predictions.disease;

        let aiHtml = `
            <div class="ai-result success">
                <h4>✅ AI Analysis Complete</h4>

                <div class="prediction-section">
                    <h5>Crop Identification</h5>
                    <div class="prediction-item">
                        <strong>Crop:</strong> ${cropPred.crop_name}
                    </div>
                    <div class="prediction-item">
                        <strong>Confidence:</strong> ${(cropPred.confidence * 100).toFixed(1)}%
                    </div>
                </div>
        `;

        if (diseasePred) {
            aiHtml += `
                <div class="prediction-section">
                    <h5>Disease Identification</h5>
                    <div class="prediction-item">
                        <strong>Condition:</strong> ${diseasePred.disease_name}
                    </div>
                    <div class="prediction-item">
                        <strong>Confidence:</strong> ${(diseasePred.confidence * 100).toFixed(1)}%
                    </div>
                </div>
            `;
        } else {
            aiHtml += `
                <div class="prediction-section">
                    <h5>Disease Identification</h5>
                    <div class="prediction-item">
                        <strong>Status:</strong> Could not identify specific disease
                    </div>
                    <div class="prediction-item">
                        <strong>Action:</strong> Please proceed with symptom selection
                    </div>
                </div>
            `;
        }

        aiHtml += `</div>`;

        analysisContainer.innerHTML = aiHtml;

        // Update confidence meter
        if (diseasePred) {
            this.updateConfidenceMeter(diseasePred.confidence * 100);
        } else if (cropPred) {
            this.updateConfidenceMeter(cropPred.confidence * 100);
        }

        // Store crop ID for later use
        this.selectedCrop = {
            crop_id: cropPred.crop_id,
            crop_name: cropPred.crop_name
        };

        // Load symptoms for the next step
        this.loadSymptomsForCrop(cropPred.crop_id);

        // Auto-add AI suggested symptoms if available
        if (result.details && result.details.disease) {
            this.addAISuggestedSymptoms(result.details.disease);
        }
    }

    updateConfidenceMeter(confidence) {
        const meterFill = document.getElementById('meterFill');
        const meterValue = document.getElementById('meterValue');

        if (meterFill && meterValue) {
            meterFill.style.width = `${confidence}%`;
            meterValue.textContent = `${confidence.toFixed(1)}%`;

            // Color coding based on confidence
            if (confidence > 70) {
                meterFill.style.background = 'linear-gradient(90deg, #4CAF50, #2E7D32)';
            } else if (confidence > 40) {
                meterFill.style.background = 'linear-gradient(90deg, #ff9800, #f57c00)';
            } else {
                meterFill.style.background = 'linear-gradient(90deg, #f44336, #d32f2f)';
            }
        }
    }

    async loadSymptomsForCrop(cropId) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/diseases/${cropId}`);
            if (!response.ok) throw new Error('Failed to load symptoms');

            const diseases = await response.json();

            // Extract all unique symptoms
            const allSymptoms = new Set();
            diseases.forEach(disease => {
                if (disease.symptoms && Array.isArray(disease.symptoms)) {
                    disease.symptoms.forEach(symptom => {
                        allSymptoms.add(symptom);
                    });
                }
            });

            this.displaySymptoms(Array.from(allSymptoms));

        } catch (error) {
            console.error('Error loading symptoms:', error);
            this.showNotification('Error loading symptoms', 'error');
        }
    }

    addAISuggestedSymptoms(diseaseDetails) {
        if (!diseaseDetails.symptoms || !Array.isArray(diseaseDetails.symptoms)) {
            return;
        }

        const aiSuggestedContainer = document.getElementById('aiSuggestedSymptoms');
        if (!aiSuggestedContainer) return;

        // Clear existing suggestions
        aiSuggestedContainer.innerHTML = '';

        // Add AI suggested symptoms
        diseaseDetails.symptoms.forEach(symptom => {
            const tag = this.createSymptomTag(symptom, true);
            aiSuggestedContainer.appendChild(tag);

            // Auto-select AI suggested symptoms
            this.selectedSymptoms.push(symptom);
        });

        // Update the manual symptoms display to show selected AI symptoms
        this.updateManualSymptomsDisplay();
    }

    updateManualSymptomsDisplay() {
        const symptomTagsContainer = document.getElementById('symptomTags');
        if (!symptomTagsContainer) return;

        // Get all symptom tags
        const tags = symptomTagsContainer.querySelectorAll('.symptom-tag');
        tags.forEach(tag => {
            const symptom = tag.dataset.symptom;
            if (this.selectedSymptoms.includes(symptom)) {
                tag.classList.add('selected');
            }
        });
    }

    displaySymptoms(symptoms) {
        const container = document.getElementById('symptomTags');
        if (!container) return;

        container.innerHTML = '';

        symptoms.forEach(symptom => {
            const tag = this.createSymptomTag(symptom, false);
            container.appendChild(tag);
        });

        // Update to show already selected symptoms
        this.updateManualSymptomsDisplay();
    }

    createSymptomTag(symptom, isAISuggestion = false) {
        const tag = document.createElement('div');
        tag.className = `symptom-tag ${isAISuggestion ? 'ai-suggested' : ''}`;
        tag.textContent = symptom;
        tag.dataset.symptom = symptom;

        tag.addEventListener('click', () => {
            this.toggleSymptom(symptom, tag);
        });

        return tag;
    }

    toggleSymptom(symptom, element) {
        const index = this.selectedSymptoms.indexOf(symptom);

        if (index === -1) {
            this.selectedSymptoms.push(symptom);
            element.classList.add('selected');
        } else {
            this.selectedSymptoms.splice(index, 1);
            element.classList.remove('selected');
        }

        this.enableNextButton(this.selectedSymptoms.length > 0 || this.aiPrediction);
    }

    addCustomSymptom() {
        const input = document.getElementById('customSymptom');
        const symptom = input.value.trim();

        if (!symptom) {
            this.showNotification('Please enter a symptom', 'warning');
            return;
        }

        if (this.selectedSymptoms.includes(symptom)) {
            this.showNotification('Symptom already added', 'warning');
            return;
        }

        this.selectedSymptoms.push(symptom);

        // Add to manual symptoms display
        const container = document.getElementById('symptomTags');
        if (container) {
            const tag = this.createSymptomTag(symptom, false);
            tag.classList.add('selected');
            container.appendChild(tag);
        }

        input.value = '';
        this.enableNextButton(true);
        this.showNotification('Custom symptom added', 'success');
    }

    async performFinalDiagnosis() {
        this.showLoading(true);

        try {
            // Get all diseases for this crop
            const diseasesResponse = await fetch(`${this.apiBaseUrl}/diseases/${this.selectedCrop.crop_id}`);
            const diseases = await diseasesResponse.json();
            const diseaseIds = diseases.map(d => d.disease_id);

            // Prepare data for diagnosis
            const diagnosisData = {
                crop_id: this.selectedCrop.crop_id,
                disease_ids: diseaseIds,
                answers: this.answers,
                symptoms: this.selectedSymptoms,
                ai_prediction: this.aiPrediction.disease || this.aiPrediction.crop
            };

            const response = await fetch(`${this.apiBaseUrl}/diagnose`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(diagnosisData)
            });

            if (!response.ok) throw new Error('Diagnosis failed');

            this.diagnosisResult = await response.json();
            this.displayFinalDiagnosis();
            this.showNotification('Final diagnosis complete!', 'success');

        } catch (error) {
            console.error('Diagnosis error:', error);
            this.showNotification(error.message || 'Error performing diagnosis', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    displayFinalDiagnosis() {
        const container = document.getElementById('finalDiagnosisContainer');
        const diagnosis = this.diagnosisResult.diagnosis;

        let icon = '🌿';
        if (diagnosis.disease.type === 'Disease') icon = '🦠';
        else if (diagnosis.disease.type === 'Nutrient Deficiency') icon = '⚠️';
        else if (diagnosis.disease.type === 'Healthy') icon = '✅';

        // Calculate overall confidence (average of AI and symptom matching)
        const aiConfidence = diagnosis.ai_confidence || 0;
        const symptomConfidence = diagnosis.confidence_score || 0;
        const overallConfidence = (aiConfidence + symptomConfidence) / 2;

        container.innerHTML = `
            <div class="final-diagnosis">
                <div class="diagnosis-header">
                    <div class="diagnosis-icon">${icon}</div>
                    <h2 class="disease-name">${diagnosis.disease.disease_name}</h2>
                    <div class="confidence-badge">
                        Overall Confidence: ${overallConfidence.toFixed(1)}%
                    </div>
                </div>

                <div class="confidence-breakdown">
                    <div class="confidence-item">
                        <span>AI Confidence:</span>
                        <span class="confidence-value ${aiConfidence > 70 ? 'high' : aiConfidence > 40 ? 'medium' : 'low'}">
                            ${aiConfidence.toFixed(1)}%
                        </span>
                    </div>
                    <div class="confidence-item">
                        <span>Symptom Match:</span>
                        <span class="confidence-value ${symptomConfidence > 70 ? 'high' : symptomConfidence > 40 ? 'medium' : 'low'}">
                            ${symptomConfidence.toFixed(1)}%
                        </span>
                    </div>
                </div>

                <div class="disease-info">
                    <h3>Diagnosis Details</h3>
                    <div class="info-grid">
                        <div class="info-item">
                            <h4>Crop</h4>
                            <p>${diagnosis.disease.crop_name}</p>
                        </div>
                        <div class="info-item">
                            <h4>Type</h4>
                            <p>${diagnosis.disease.type}</p>
                        </div>
                        <div class="info-item">
                            <h4>AI Identified</h4>
                            <p>${this.aiPrediction.disease ? 'Yes' : 'No'}</p>
                        </div>
                    </div>

                    <div class="overview-item">
                        <h4>Overview</h4>
                        <p>${diagnosis.disease.disease_overview || 'No overview available'}</p>
                    </div>
                </div>

                ${diagnosis.matched_symptoms.length > 0 ? `
                <div class="matched-symptoms">
                    <h4>Matched Symptoms</h4>
                    <div class="symptom-tags">
                        ${diagnosis.matched_symptoms.map(symptom => `
                            <div class="symptom-tag selected">${symptom}</div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                ${diagnosis.advisories && diagnosis.advisories.length > 0 ? `
                <div class="advisories-section">
                    <h3>Management Recommendations</h3>
                    <div class="advisory-content">
                        ${diagnosis.advisories.map(adv => `
                            <div class="advisory-item">
                                <strong>${adv.advisory_type}:</strong> ${adv.advisory_text}
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                ${this.diagnosisResult.recommendations && this.diagnosisResult.recommendations.length > 0 ? `
                <div class="additional-recommendations">
                    <h3>Additional Recommendations</h3>
                    ${this.diagnosisResult.recommendations.map(rec => `
                        <div class="recommendation-item ${rec.type}">
                            <strong>${rec.type.replace('_', ' ').toUpperCase()}:</strong> ${rec.message}
                        </div>
                    `).join('')}
                </div>
                ` : ''}

                <div class="action-buttons">
                    <button class="btn btn-secondary" onclick="window.agriAID.restartDiagnosis()">
                        <span class="btn-icon">🔄</span> Start New Diagnosis
                    </button>
                    <button class="btn" onclick="window.agriAID.downloadReport()">
                        <span class="btn-icon">📄</span> Download Report
                    </button>
                    <button class="btn" onclick="window.agriAID.shareResults()">
                        <span class="btn-icon">📤</span> Share Results
                    </button>
                </div>
            </div>
        `;
    }

    nextStep() {
        if (this.currentStep >= this.totalSteps) return;

        // Validate current step
        if (!this.validateCurrentStep()) {
            return;
        }

        // Execute step-specific actions
        switch (this.currentStep) {
            case 1:
                if (!this.uploadedImage) {
                    this.showNotification('Please upload an image first', 'warning');
                    return;
                }
                break;

            case 2:
                // AI analysis step - automatically moves forward
                break;

            case 3:
                if (this.selectedSymptoms.length === 0 && !this.aiPrediction) {
                    this.showNotification('Please select at least one symptom or rely on AI analysis', 'warning');
                    return;
                }
                this.performFinalDiagnosis();
                break;
        }

        // Hide current step
        this.hideCurrentStep();

        // Move to next step
        this.currentStep++;

        // Update UI
        this.updateUI();

        // Scroll to top
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    prevStep() {
        if (this.currentStep <= 1) return;

        this.hideCurrentStep();
        this.currentStep--;
        this.updateUI();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    validateCurrentStep() {
        switch (this.currentStep) {
            case 1:
                return this.uploadedImage !== null;
            case 3:
                return this.selectedSymptoms.length > 0 || this.aiPrediction !== null;
            default:
                return true;
        }
    }

    updateUI() {
        // Update progress bar
        const progress = (this.currentStep / this.totalSteps) * 100;
        const progressFill = document.getElementById('progressFill');
        if (progressFill) {
            progressFill.style.width = `${progress}%`;
        }

        // Update step indicators
        document.querySelectorAll('.progress-step').forEach((step, index) => {
            const stepNumber = index + 1;

            step.classList.remove('active', 'completed');

            if (stepNumber === this.currentStep) {
                step.classList.add('active');
            } else if (stepNumber < this.currentStep) {
                step.classList.add('completed');
            }
        });

        // Show current step
        document.querySelectorAll('.step').forEach(step => {
            step.classList.remove('active');
        });

        const currentStepElement = document.getElementById(`step${this.currentStep}`);
        if (currentStepElement) {
            currentStepElement.classList.add('active');
        }

        // Update navigation buttons
        this.updateNavigationButtons();
    }

    updateNavigationButtons() {
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');

        // Previous button
        prevBtn.disabled = this.currentStep === 1;

        // Next button
        if (this.currentStep === this.totalSteps) {
            nextBtn.style.display = 'none';
            prevBtn.style.display = 'none';
        } else {
            nextBtn.style.display = 'flex';
            prevBtn.style.display = 'flex';

            nextBtn.innerHTML = this.currentStep === this.totalSteps - 1 ?
                'Get Final Diagnosis <span class="btn-icon">🚀</span>' :
                'Next <span class="btn-icon">→</span>';
        }

        // Update next button state
        this.updateNextButtonState();
    }

    updateNextButtonState() {
        const nextBtn = document.getElementById('nextBtn');
        if (!nextBtn) return;

        const enabled = this.validateCurrentStep();
        nextBtn.disabled = !enabled;
    }

    enableNextButton(enabled = true) {
        const nextBtn = document.getElementById('nextBtn');
        if (nextBtn) {
            nextBtn.disabled = !enabled;
        }
    }

    // Utility methods (showLoading, showNotification, restartDiagnosis, downloadReport, shareResults)
    // ... (same as previous implementation)
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.agriAID = new AgriAID();
});