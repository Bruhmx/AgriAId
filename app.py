import os
from datetime import datetime
import json

from flask import Flask, render_template, request, session, jsonify, flash, url_for, make_response, Response
from werkzeug.utils import secure_filename, redirect, send_from_directory

from auth import login_required
from db_config import get_db_cursor, get_db_cursor_readonly, get_db, return_db
from predictor import predict_crop, predict_disease, get_crop_display_name, get_disease_display_name
from user_routes import register_user_routes

import user_routes
app = Flask(__name__)
app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = "static/uploads"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Create uploads directory if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Create feedback uploads directory
os.makedirs('static/uploads/feedback', exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# ========== DATABASE SAVE FUNCTIONS ==========
def save_initial_diagnosis(user_id, image_file, crop, disease_data):
    """Save initial AI diagnosis to database with image as BLOB"""
    try:
        # Read image as binary
        image_file.seek(0)  # Ensure we're at the start of the file
        image_binary = image_file.read()

        # Combine treatment info into recommendations
        recommendations = f"Manual: {disease_data.get('manual_treatment', 'N/A')}. "
        recommendations += f"Organic: {disease_data.get('organic_treatment', 'N/A')}. "
        recommendations += f"Chemical: {disease_data.get('chemical_treatment', 'N/A')}."

        # Insert with image BLOB
        with get_db_cursor() as cur:
            query = """
            INSERT INTO diagnosis_history 
            (user_id, image, crop, disease_detected, 
             confidence, symptoms, recommendations, for_training)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """
            cur.execute(query, (
                user_id,
                image_binary,  # Store image directly in database
                crop,
                disease_data['name'],
                disease_data['confidence'],
                disease_data.get('symptoms', ''),
                recommendations,
                True  # for_training
            ))
            
            diagnosis_id = cur.fetchone()[0]

        print(f"✅ Diagnosis saved with ID: {diagnosis_id}, Image size: {len(image_binary)} bytes")
        return diagnosis_id
    except Exception as e:
        print(f"❌ Error saving initial diagnosis: {e}")
        import traceback
        traceback.print_exc()
        return None


def update_diagnosis_with_answers(diagnosis_id, answers_data, summary_data):
    """Update diagnosis with expert answers and summary"""
    try:
        with get_db_cursor() as cur:
            cur.execute("""
                UPDATE diagnosis_history 
                SET expert_answers = %s,
                    expert_summary = %s,
                    final_confidence_level = %s
                WHERE id = %s
            """, (
                json.dumps(answers_data),
                json.dumps(summary_data),
                summary_data.get('confidence', 'Possible'),
                diagnosis_id
            ))
        return True
    except Exception as e:
        print(f"❌ Error updating diagnosis: {e}")
        return False


def save_exported_training_data(diagnosis_ids):
    """Mark images as used in training"""
    if not diagnosis_ids:
        return

    try:
        with get_db_cursor() as cur:
            placeholders = ','.join(['%s'] * len(diagnosis_ids))
            cur.execute(f"""
                UPDATE diagnosis_history 
                SET training_used = TRUE,
                    image_processed = TRUE
                WHERE id IN ({placeholders})
            """, diagnosis_ids)
    except Exception as e:
        print(f"❌ Error marking training data: {e}")


# ========== IMAGE SERVING ROUTE ==========
@app.route('/diagnosis-image/<int:diagnosis_id>')
@login_required
def diagnosis_image(diagnosis_id):
    """Serve diagnosis image from BLOB"""
    user_id = session['user_id']
    
    with get_db_cursor() as cur:
        cur.execute("""
            SELECT image FROM diagnosis_history
            WHERE id = %s AND user_id = %s
        """, (diagnosis_id, user_id))

        result = cur.fetchone()

    if result and result[0]:  # result[0] is the image BLOB
        return Response(result[0], mimetype='image/jpeg')  # or image/png
    else:
        # Return a default placeholder image
        return send_from_directory('static', 'images/placeholder.jpg')

@app.route("/")
def index():
    """Home page with system description"""
    # Only clear diagnosis data if needed
    diagnosis_keys = [
        'crop', 'crop_display', 'crop_confidence',
        'diseases', 'question_tree', 'all_questions_flat',
        'user_answers', 'pending_diagnosis', 'pending_questions'
    ]

    for key in diagnosis_keys:
        session.pop(key, None)

    return render_template("index.html")

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_image():
    """Handle image upload and show AI diagnosis results"""
    if request.method == "POST":
        # Check if file was uploaded
        if 'image' not in request.files:
            return render_template("upload.html", error="No file selected")

        file = request.files['image']

        if file.filename == '':
            return render_template("upload.html", error="No file selected")

        if not allowed_file(file.filename):
            return render_template("upload.html", error="File type not allowed. Please upload an image.")

        # Store file position for later use
        file.seek(0)

        # Create a temporary file for AI processing
        temp_filename = secure_filename(f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        file.save(temp_filepath)

        try:
            # Step 1: Crop Identification
            crop, crop_conf = predict_crop(temp_filepath)

            # Validate crop detection
            valid_crops = ['corn', 'rice']
            if crop not in valid_crops or float(crop_conf) < 0.8:
                if os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
                return render_template("upload.html",
                                       error="Invalid image - Please upload a clear image of corn or rice leaves.")

            # Step 2: Disease Prediction
            diseases = predict_disease(temp_filepath, crop)

            # Store in session
            session['crop'] = crop
            session['crop_display'] = get_crop_display_name(crop)

            # Get disease details from database for all detected diseases
            disease_results = []
            for disease_name, confidence in diseases[:3]:
                # Get disease information
                with get_db_cursor() as cur:
                    cur.execute("""
                        SELECT * FROM disease_info 
                        WHERE crop = %s AND disease_code = %s
                    """, (crop, disease_name))

                    disease_details_row = cur.fetchone()
                    
                    # Convert to dict with column names (assuming standard order)
                    if disease_details_row:
                        disease_details = {
                            'cause': disease_details_row[3] if len(disease_details_row) > 3 else 'Information not available',
                            'symptoms': disease_details_row[4] if len(disease_details_row) > 4 else 'Symptoms information not available',
                            'manual_treatment': disease_details_row[8] if len(disease_details_row) > 8 else 'Remove affected leaves and maintain proper spacing.',
                            'organic_treatment': disease_details_row[5] if len(disease_details_row) > 5 else 'Apply neem oil or baking soda solution.',
                            'chemical_treatment': disease_details_row[6] if len(disease_details_row) > 6 else 'Consult with agricultural expert for chemical recommendations.',
                            'prevention': disease_details_row[7] if len(disease_details_row) > 7 else 'Practice crop rotation and maintain field hygiene.'
                        }
                    else:
                        disease_details = {
                            'cause': 'Information not available',
                            'symptoms': 'Symptoms information not available',
                            'manual_treatment': 'Remove affected leaves and maintain proper spacing.',
                            'organic_treatment': 'Apply neem oil or baking soda solution.',
                            'chemical_treatment': 'Consult with agricultural expert for chemical recommendations.',
                            'prevention': 'Practice crop rotation and maintain field hygiene.'
                        }

                # Get sample images
                with get_db_cursor() as cur:
                    cur.execute("""
                        SELECT id, image_title as title, 
                               image_description as description, severity_level as severity
                        FROM disease_samples 
                        WHERE crop = %s AND disease_code = %s 
                        ORDER BY display_order
                    """, (crop, disease_name))

                    sample_images = []
                    for row in cur.fetchall():
                        sample_images.append({
                            'id': row[0],
                            'title': row[1],
                            'description': row[2],
                            'severity': row[3],
                            'url': url_for('get_disease_sample_image', sample_id=row[0])
                        })

                disease_result = {
                    'code': disease_name,
                    'name': get_disease_display_name(disease_name),
                    'confidence': float(confidence) * 100,
                    'cause': disease_details.get('cause', 'Information not available'),
                    'symptoms': disease_details.get('symptoms', 'Symptoms information not available'),
                    'manual_treatment': disease_details.get('manual_treatment', 'Remove affected leaves and maintain proper spacing.'),
                    'organic_treatment': disease_details.get('organic_treatment', 'Apply neem oil or baking soda solution.'),
                    'chemical_treatment': disease_details.get('chemical_treatment', 'Consult with agricultural expert for chemical recommendations.'),
                    'prevention': disease_details.get('prevention', 'Practice crop rotation and maintain field hygiene.'),
                    'sample_images': sample_images
                }
                disease_results.append(disease_result)

            # ===== SAVE TO DATABASE WITH IMAGE BLOB =====
            user_id = session.get('user_id')
            if user_id and disease_results:
                # Go back to beginning of file for reading
                file.seek(0)

                diagnosis_id = save_initial_diagnosis(
                    user_id=user_id,
                    image_file=file,  # Pass the file object directly
                    crop=crop,
                    disease_data=disease_results[0]  # Primary disease
                )

                if diagnosis_id:
                    session['current_diagnosis_id'] = diagnosis_id
                    print(f"✅ Diagnosis saved with ID: {diagnosis_id}")
                else:
                    print("⚠️ Failed to save diagnosis to database")

            # Clean up temp file
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)

            # Store AI results in session
            session['ai_diagnosis'] = {
                'primary': disease_results[0],
                'alternatives': disease_results[1:] if len(disease_results) > 1 else [],
                'crop_original': crop,
                'crop': session['crop_display']
            }

            # Render results page with AI diagnosis
            return render_template("ai_results.html",
                                   diagnosis=session['ai_diagnosis'],
                                   diagnosis_id=session.get('current_diagnosis_id', 0))

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            # Clean up temp file if it exists
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
            return render_template("upload.html", error="Error processing image. Please try again.")

    return render_template("upload.html")


@app.route("/optional-questions/<disease_code>")
@login_required
def optional_questions(disease_code):
    """Optional expert questions for additional information (doesn't affect AI results)"""
    if 'ai_diagnosis' not in session:
        return redirect("/upload")

    crop = session.get('crop')

    # Get questions for this disease
    with get_db_cursor() as cur:
        cur.execute("""
            SELECT q.id, q.question_text, q.yes_score, q.no_score, 
                   q.question_category, q.priority, q.depends_on, q.show_if_answer,
                   COALESCE(di.disease_name, q.target) as disease_name
            FROM questions q
            LEFT JOIN disease_info di ON q.crop = di.crop AND q.target = di.disease_code
            WHERE q.crop = %s AND q.target = %s
            ORDER BY q.priority, q.id
        """, (crop, disease_code))

        all_questions_rows = cur.fetchall()
        all_questions = []
        for row in all_questions_rows:
            all_questions.append({
                'id': row[0],
                'question_text': row[1],
                'yes_score': row[2],
                'no_score': row[3],
                'question_category': row[4],
                'priority': row[5],
                'depends_on': row[6],
                'show_if_answer': row[7],
                'disease_name': row[8]
            })

        # Get root questions (no dependencies)
        root_questions = [q for q in all_questions if q['depends_on'] is None]

    return render_template("optional_questions.html",
                           disease_code=disease_code,
                           disease_name=get_disease_display_name(disease_code),
                           crop=session.get('crop_display'),
                           questions=root_questions,
                           all_questions=all_questions,
                           diagnosis_id=session.get('current_diagnosis_id', 0))


@app.route("/api/get-questions-for-disease")
def get_questions_for_disease():
    """API endpoint to get questions for a specific disease"""
    disease_code = request.args.get('disease_code')
    crop = request.args.get('crop')

    print(f"🔵 API CALLED - disease_code: {disease_code}, crop: {crop}")

    if not disease_code or not crop:
        return jsonify({'success': False, 'error': 'Missing parameters'})

    try:
        with get_db_cursor() as cur:
            # Get all questions for this disease
            cur.execute("""
                SELECT id, question_text, question_category, display_order
                FROM questions 
                WHERE crop = %s AND disease_code = %s
                ORDER BY display_order, id
            """, (crop, disease_code))

            questions = []
            for row in cur.fetchall():
                questions.append({
                    'id': row[0],
                    'question_text': row[1],
                    'question_category': row[2],
                    'display_order': row[3]
                })

        return jsonify({
            'success': True,
            'questions': questions,
            'count': len(questions)
        })

    except Exception as e:
        print(f"Error fetching questions: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route("/api/get-question-insights", methods=["POST"])
def get_question_insights():
    """Generate insights from answers - all answers count toward confidence level"""
    try:
        data = request.get_json()
        answers = data.get('answers', {})
        disease_code = data.get('disease_code')
        crop = data.get('crop')
        diagnosis_id = data.get('diagnosis_id')

        if not disease_code or not answers or not crop:
            return jsonify({'success': False, 'error': 'Missing data'})

        # Get questions that were answered
        placeholders = ','.join(['%s'] * len(answers.keys()))
        query = f"""
            SELECT id, question_text, question_category
            FROM questions
            WHERE crop = %s AND disease_code = %s AND id IN ({placeholders})
        """

        params = [crop, disease_code] + list(answers.keys())
        
        with get_db_cursor() as cur:
            cur.execute(query, params)
            questions_rows = cur.fetchall()
            
            questions = []
            for row in questions_rows:
                questions.append({
                    'id': row[0],
                    'question_text': row[1],
                    'question_category': row[2]
                })

        # Calculate statistics
        total_yes = 0
        total_no = 0
        total_unknown = 0
        insights = []
        answers_data = []  # For database storage

        for q in questions:
            q_id = str(q['id'])
            answer = answers.get(q_id)
            category = q['question_category']

            answers_data.append({
                'question_id': int(q_id),
                'question_text': q['question_text'],
                'category': category,
                'answer': answer
            })

            if answer == 'yes':
                total_yes += 1
                insights.append({
                    'type': 'match',
                    'text': f"✓ You confirmed: \"{q['question_text']}\""
                })
            elif answer == 'no':
                total_no += 1
                insights.append({
                    'type': 'note',
                    'text': f"ℹ You did not observe: \"{q['question_text']}\""
                })
            else:
                total_unknown += 1
                insights.append({
                    'type': 'info',
                    'text': f"? You were unsure about: \"{q['question_text']}\""
                })

        total_answered = total_yes + total_no + total_unknown
        yes_ratio = (total_yes / total_answered * 100) if total_answered > 0 else 0

        # Determine confidence level
        if yes_ratio >= 70:
            confidence_level = "Very Likely"
            confidence_color = "success"
            recommendation = "Proceed with recommended treatments"
        elif yes_ratio >= 50:
            confidence_level = "Likely"
            confidence_color = "warning"
            recommendation = "Consider treatment options"
        elif yes_ratio >= 30:
            confidence_level = "Possible"
            confidence_color = "orange"
            recommendation = "Monitor and consult expert"
        elif yes_ratio >= 10:
            confidence_level = "Unlikely"
            confidence_color = "danger"
            recommendation = "Consider other possibilities"
        else:
            confidence_level = "Very Unlikely"
            confidence_color = "secondary"
            recommendation = "Consider alternative diagnosis"

        summary_data = {
            'yes_count': total_yes,
            'no_count': total_no,
            'unknown_count': total_unknown,
            'total_answered': total_answered,
            'confidence': confidence_level,
            'color': confidence_color,
            'recommendation': recommendation,
            'yes_ratio': round(yes_ratio, 1)
        }

        # Save to database if diagnosis_id is provided
        if diagnosis_id:
            update_diagnosis_with_answers(diagnosis_id, answers_data, summary_data)

        return jsonify({
            'success': True,
            'insights': insights,
            'summary': summary_data
        })

    except Exception as e:
        print(f"Error generating insights: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/my-diagnoses')
@login_required
def my_diagnoses():
    user_id = session['user_id']
    
    with get_db_cursor() as cur:
        cur.execute("""
            SELECT id, crop, disease_detected, confidence, created_at 
            FROM diagnosis_history
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))

        diagnoses = []
        for row in cur.fetchall():
            diagnoses.append({
                'id': row[0],
                'crop': row[1],
                'disease_detected': row[2],
                'confidence': row[3],
                'created_at': row[4]
            })

    return render_template('history.html', diagnoses=diagnoses)

@app.route("/export-training-data", methods=["POST"])
@login_required
def export_training_data():
    """Export unused images for training (admin only)"""
    # Check if user is admin
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    try:
        data = request.get_json() or {}
        crop = data.get('crop')
        disease = data.get('disease')
        limit = data.get('limit', 1000)
        min_confidence = data.get('min_confidence', 80)

        # Build query - Note: We need to export images from database
        query = """
            SELECT id, image, crop, disease_detected, confidence
            FROM diagnosis_history 
            WHERE for_training = TRUE 
            AND training_used = FALSE
            AND confidence >= %s
        """
        params = [min_confidence]

        if crop:
            query += " AND crop = %s"
            params.append(crop)

        if disease:
            query += " AND disease_detected = %s"
            params.append(disease)

        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        with get_db_cursor() as cur:
            cur.execute(query, params)
            images_rows = cur.fetchall()
            
            images = []
            for row in images_rows:
                images.append({
                    'id': row[0],
                    'image': row[1],
                    'crop': row[2],
                    'disease_detected': row[3],
                    'confidence': row[4]
                })

        if not images:
            return jsonify({'success': True, 'message': 'No new images to export', 'exported_count': 0})

        # Create export directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_dir = f'static/training_exports/{timestamp}'
        os.makedirs(export_dir, exist_ok=True)

        exported_ids = []
        exported_files = []

        for img in images:
            # Create crop/disease folders
            crop_dir = os.path.join(export_dir, img['crop'])
            disease_dir = os.path.join(crop_dir, img['disease_detected'].replace(' ', '_'))
            os.makedirs(disease_dir, exist_ok=True)

            # Save image from BLOB to file
            if img['image']:
                filename = f"{img['id']}_{img['confidence']}conf.jpg"
                filepath = os.path.join(disease_dir, filename)

                with open(filepath, 'wb') as f:
                    f.write(img['image'])

                exported_files.append(filepath)
                exported_ids.append(img['id'])

        # Mark as used
        if exported_ids:
            save_exported_training_data(exported_ids)

        return jsonify({
            'success': True,
            'exported_count': len(exported_ids),
            'export_path': export_dir,
            'files': exported_files[:10]
        })

    except Exception as e:
        print(f"Error exporting training data: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/training-stats")
@login_required
def training_stats():
    """Get statistics about training data (admin only)"""
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    try:
        with get_db_cursor() as cur:
            # Total counts
            cur.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN for_training = TRUE THEN 1 ELSE 0 END) as available_for_training,
                    SUM(CASE WHEN training_used = TRUE THEN 1 ELSE 0 END) as used_in_training,
                    SUM(CASE WHEN image_processed = TRUE THEN 1 ELSE 0 END) as processed,
                    AVG(confidence) as avg_confidence
                FROM diagnosis_history
            """)
            totals_row = cur.fetchone()
            
            totals = {
                'total': totals_row[0] or 0,
                'available_for_training': totals_row[1] or 0,
                'used_in_training': totals_row[2] or 0,
                'processed': totals_row[3] or 0,
                'avg_confidence': totals_row[4] or 0
            }

            # Breakdown by crop
            cur.execute("""
                SELECT 
                    crop,
                    COUNT(*) as total,
                    SUM(CASE WHEN training_used = TRUE THEN 1 ELSE 0 END) as used
                FROM diagnosis_history
                WHERE for_training = TRUE
                GROUP BY crop
            """)
            by_crop = []
            for row in cur.fetchall():
                by_crop.append({
                    'crop': row[0],
                    'total': row[1],
                    'used': row[2]
                })

            # Breakdown by disease
            cur.execute("""
                SELECT 
                    disease_detected,
                    COUNT(*) as total,
                    AVG(confidence) as avg_confidence
                FROM diagnosis_history
                WHERE for_training = TRUE
                GROUP BY disease_detected
                ORDER BY total DESC
                LIMIT 10
            """)
            by_disease = []
            for row in cur.fetchall():
                by_disease.append({
                    'disease_detected': row[0],
                    'total': row[1],
                    'avg_confidence': row[2]
                })

        return jsonify({
            'success': True,
            'stats': {
                'totals': totals,
                'by_crop': by_crop,
                'by_disease': by_disease
            }
        })

    except Exception as e:
        print(f"Error getting training stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/get-diagnosis", methods=["POST"])
def get_diagnosis():
    """Process answers and show diagnosis results"""
    print("\n" + "=" * 70)
    print("🎯 PROCESSING DIAGNOSIS FROM QUESTION FORM")
    print("=" * 70)

    # Check if we have the necessary session data
    if 'diseases' not in session:
        print("❌ No diseases in session, redirecting to upload")
        return redirect("/upload")

    try:
        # Get crop and image info
        crop = session.get('crop', 'Unknown')
        crop_display = session.get('crop_display', 'Unknown Crop')

        print(f"Crop: {crop_display}")

        # ========== COLLECT ALL ANSWERS ==========
        all_answers = {}
        yes_answers = 0
        no_answers = 0
        unknown_answers = 0
        answered_count = 0

        # Get all form data
        for key, value in request.form.items():
            if key.startswith('q_'):
                question_id = key[2:]  # Remove 'q_' prefix
                all_answers[question_id] = value
                answered_count += 1

                if value == 'yes':
                    yes_answers += 1
                elif value == 'no':
                    no_answers += 1
                else:
                    unknown_answers += 1

        # ========== CALCULATE DISEASE SCORES ==========
        if 'all_questions_flat' not in session:
            print("❌ No questions in session")
            return render_template("error.html", error="No questions found in session")

        all_questions = session['all_questions_flat']
        diseases = session.get('diseases', [])

        # Reset scores
        for disease in diseases:
            disease['score'] = 0
            disease['matched_questions'] = []

        # Calculate scores for each disease based on answers
        for question in all_questions:
            q_id = str(question['id'])
            if q_id in all_answers:
                answer = all_answers[q_id]
                disease_code = question['disease_code']

                # Find the disease in our list
                for disease in diseases:
                    if disease['code'] == disease_code:
                        # Add score based on answer
                        if answer == 'yes':
                            score_to_add = question['yes_score']
                        elif answer == 'no':
                            score_to_add = question['no_score']
                        else:  # unknown
                            score_to_add = 0

                        disease['score'] += score_to_add
                        disease['matched_questions'].append({
                            'question': question['question_text'],
                            'answer': answer,
                            'score_added': score_to_add
                        })
                        break

        print("\n📈 Disease Scores:")
        for disease in diseases:
            print(f"  {disease['name']}: {disease['score']} points")

        # ========== CALCULATE FINAL CONFIDENCE ==========
        # Find best disease (highest score)
        if not diseases:
            return render_template("error.html", error="No diseases found for diagnosis")

        best_disease = max(diseases, key=lambda x: x['score'])

        # Get ML confidence from the disease data
        ml_confidence = best_disease.get('confidence', 50)

        # Calculate question-based confidence
        question_score = best_disease['score']

        # Create list of questions that were ACTUALLY ANSWERED for this disease
        disease_questions_answered = []
        for q_id in all_answers:  # all_answers contains only answered questions
            # Find this question in all_questions
            for q in all_questions:
                if str(q['id']) == q_id and q['disease_code'] == best_disease['code']:
                    disease_questions_answered.append(q)
                    break

        # Calculate max possible from ANSWERED questions only
        if disease_questions_answered:
            max_possible = sum(max(q['yes_score'], q['no_score'], 0) for q in disease_questions_answered)
            question_percentage = (question_score / max_possible) * 100 if max_possible > 0 else 50
        else:
            max_possible = 0
            question_percentage = 50  # Neutral if no questions answered

        # Blend ML and question confidence (50/50 split)
        final_confidence = (ml_confidence * 0.5) + (question_percentage * 0.5)
        final_confidence = max(10, min(95, final_confidence))  # Keep between 10-95%

        # Determine confidence level
        if final_confidence < 40:
            confidence_label = "Low Confidence"
        elif final_confidence < 60:
            confidence_label = "Possible"
        elif final_confidence < 75:
            confidence_label = "Likely"
        elif final_confidence < 90:
            confidence_label = "Very Likely"
        else:
            confidence_label = "Confirmed"

        # Determine severity based on confidence and score
        if final_confidence < 50:
            severity = "Mild"
        elif final_confidence < 75:
            severity = "Moderate"
        else:
            severity = "Severe"

        print(f"\n🏆 Best Match: {best_disease['name']}")
        print(f"  ML Confidence: {ml_confidence:.1f}%")
        print(f"  Question Score: {question_score}/{max_possible}")
        print(f"  Question Percentage: {question_percentage:.1f}%")
        print(f"  Final Confidence: {final_confidence:.1f}% ({confidence_label})")

        # ========== GET DISEASE DETAILS FROM DATABASE ==========
        with get_db_cursor() as cur:
            # Get disease details
            cur.execute("""
                SELECT * FROM disease_info 
                WHERE crop = %s AND disease_code = %s
            """, (crop, best_disease['code']))

            disease_details_row = cur.fetchone()
            
            # Convert to dict
            if disease_details_row:
                disease_details = {
                    'cause': disease_details_row[3] if len(disease_details_row) > 3 else 'Information not available',
                    'symptoms': disease_details_row[4] if len(disease_details_row) > 4 else 'Symptoms information not available',
                    'organic_treatment': disease_details_row[5] if len(disease_details_row) > 5 else 'Apply neem oil or baking soda solution.',
                    'chemical_treatment': disease_details_row[6] if len(disease_details_row) > 6 else 'Consult with agricultural expert for chemical recommendations.',
                    'prevention': disease_details_row[7] if len(disease_details_row) > 7 else 'Practice crop rotation and maintain field hygiene.',
                    'manual_treatment': disease_details_row[8] if len(disease_details_row) > 8 else 'Remove affected leaves and maintain proper spacing.'
                }
            else:
                disease_details = {
                    'cause': 'Information not available',
                    'symptoms': 'Symptoms information not available',
                    'organic_treatment': 'Apply neem oil or baking soda solution.',
                    'chemical_treatment': 'Consult with agricultural expert for chemical recommendations.',
                    'prevention': 'Practice crop rotation and maintain field hygiene.',
                    'manual_treatment': 'Remove affected leaves and maintain proper spacing.'
                }

            # Get sample images for this disease
            cur.execute("""
                SELECT id, image_title as title, 
                      image_description as description, severity_level as severity
                FROM disease_samples 
                WHERE crop = %s AND disease_code = %s 
                ORDER BY display_order
            """, (crop, best_disease['code']))

            sample_images = []
            for row in cur.fetchall():
                sample_images.append({
                    'id': row[0],
                    'title': row[1],
                    'description': row[2],
                    'severity': row[3],
                    'url': url_for('get_disease_sample_image', sample_id=row[0])
                })

        # Get diagnosis_id from session for the image URL
        diagnosis_id = session.get('current_diagnosis_id', 0)

        # ========== PREPARE DATA FOR RESULTS.HTML TEMPLATE ==========
        result = {
            'disease': best_disease['name'],
            'disease_code': best_disease['code'],
            'severity': severity,
            'confidence': round(final_confidence, 1),
            'crop': crop_display,
            'diagnosis_id': diagnosis_id,  # Pass diagnosis_id for image URL
            'cause': disease_details.get('cause', 'Information not available'),
            'symptoms': disease_details.get('symptoms', 'Symptoms information not available'),
            'manual_treatment': disease_details.get('manual_treatment', 'Remove affected leaves and maintain proper spacing.'),
            'organic_treatment': disease_details.get('organic_treatment', 'Apply neem oil or baking soda solution.'),
            'chemical_treatment': disease_details.get('chemical_treatment', 'Consult with agricultural expert for chemical recommendations.'),
            'prevention': disease_details.get('prevention', 'Practice crop rotation and maintain field hygiene.'),
            'sample_images': sample_images,
            'ml_confidence': ml_confidence,
            'question_score': question_score,
            'max_possible': max_possible,
            'answered_count': answered_count,
            'yes_count': yes_answers,
            'no_count': no_answers
        }

        print("\n✅ Diagnosis processing complete!")
        print("=" * 70)

        # Render results.html template with the 'result' dictionary
        return render_template("results.html", result=result)

    except Exception as e:
        print(f"\n❌ ERROR in get_diagnosis: {str(e)}")
        import traceback
        traceback.print_exc()
        return render_template("error.html",
                               error=f"Diagnosis failed: {str(e)}",
                               crop=session.get('crop_display', 'Unknown'))


# Register user routes
register_user_routes(app)

# ========== STATIC PAGES ==========
@app.route("/privacy")
def privacy():
    """Privacy policy page"""
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    """Terms of service page"""
    return render_template("terms.html")

@app.route("/faq")
def faq():
    """FAQ page"""
    return render_template("faq.html")

@app.route("/user-guide")
@app.route("/how-it-works")
def user_guide():
    """User guide / How it works page"""
    return render_template("user_guide.html")  # Using underscore and .html extension

# ========== TEST AND DEBUG ROUTES ==========

@app.route("/test-db")
def test_db():
    """Test database connection"""
    try:
        with get_db_cursor() as cur:
            cur.execute("SELECT 1 as test")
            result = cur.fetchone()
        return jsonify({"success": True, "message": "Database connection working"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/debug-scoring")
def debug_scoring():
    """Debug page to show scoring logic"""
    if 'all_questions_flat' not in session:
        return "No questions in session. Upload an image first."

    questions_by_disease = {}
    for q in session['all_questions_flat']:
        if q['disease_code'] not in questions_by_disease:
            questions_by_disease[q['disease_code']] = []
        questions_by_disease[q['disease_code']].append(q)

    html = "<h1>Scoring Debug</h1>"
    html += "<h3>Diseases in session:</h3>"
    for d in session.get('diseases', []):
        html += f"<p><strong>{d['code']}</strong>: ML Confidence = {d.get('confidence', 50)}%</p>"

    html += "<h3>Questions by Disease:</h3>"
    for disease_code, questions in questions_by_disease.items():
        html += f"<h4>{disease_code} ({len(questions)} questions):</h4>"
        for q in questions:
            html += f"<p>Q{q['id']}: {q['question_text'][:80]}... (Yes: +{q['yes_score']}, No: +{q['no_score']})</p>"

    return html


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """API endpoint for mobile apps"""
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400

    file = request.files['image']

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Get predictions
        crop, crop_conf = predict_crop(filepath)
        diseases = predict_disease(filepath, crop)

        # Clean up
        if os.path.exists(filepath):
            os.remove(filepath)

        return jsonify({
            'crop': get_crop_display_name(crop),
            'crop_confidence': float(crop_conf) * 100,
            'diseases': [
                {
                    'name': get_disease_display_name(d[0]),
                    'code': d[0],
                    'confidence': float(d[1]) * 100
                }
                for d in diseases[:3]
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/stress-test")
def stress_test():
    """Test connection pool with multiple simultaneous connections"""
    import threading

    results = []

    def test_connection(i):
        try:
            with get_db_cursor() as cur:
                cur.execute("SELECT 1 as test")
                result = cur.fetchone()
            results.append(f"Connection {i}: OK")
        except Exception as e:
            results.append(f"Connection {i}: ERROR - {str(e)}")

    # Create 20 threads to test pool
    threads = []
    for i in range(20):
        t = threading.Thread(target=test_connection, args=(i,))
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join()

    return jsonify({
        "success": True,
        "results": results,
        "total": len(results),
        "success_count": len([r for r in results if "OK" in r])
    })

@app.route("/about")
def about():
    """System description page"""
    return render_template("about.html")

@app.route("/api/disease-info")
def get_disease_info():
    """API endpoint to get detailed disease information"""
    crop = request.args.get('crop')
    disease_code = request.args.get('disease')

    if not crop or not disease_code:
        return jsonify({'success': False, 'error': 'Missing parameters'})

    try:
        with get_db_cursor() as cur:
            # Get disease information
            cur.execute("""
                SELECT * FROM disease_info 
                WHERE crop = %s AND disease_code = %s
            """, (crop, disease_code))

            disease_data_row = cur.fetchone()

            if not disease_data_row:
                return jsonify({'success': False, 'error': 'Disease not found'})

            # Convert to dict
            disease_data = {
                'id': disease_data_row[0],
                'disease_code': disease_data_row[1],
                'crop': disease_data_row[2],
                'cause': disease_data_row[3],
                'symptoms': disease_data_row[4],
                'organic_treatment': disease_data_row[5],
                'chemical_treatment': disease_data_row[6],
                'prevention': disease_data_row[7],
                'manual_treatment': disease_data_row[8],
                'created_at': disease_data_row[9]
            }

            # Get all sample images for this disease
            cur.execute("""
                SELECT id, image_title as title, 
                       image_description as description, severity_level as severity
                FROM disease_samples 
                WHERE crop = %s AND disease_code = %s 
                ORDER BY display_order
            """, (crop, disease_code))

            sample_images = []
            for row in cur.fetchall():
                sample_images.append({
                    'id': row[0],
                    'title': row[1],
                    'description': row[2],
                    'severity': row[3],
                    'url': url_for('get_disease_sample_image', sample_id=row[0])
                })

        return jsonify({
            'success': True,
            'disease_name': get_disease_display_name(disease_code),
            'crop_display': get_crop_display_name(crop),
            'cause': disease_data.get('cause', 'Information not available'),
            'symptoms': disease_data.get('symptoms', 'No symptoms described'),
            'organic_treatment': disease_data.get('organic_treatment', 'Not specified'),
            'chemical_treatment': disease_data.get('chemical_treatment', 'Not specified'),
            'prevention': disease_data.get('prevention', 'Not specified'),
            'manual_treatment': disease_data.get('manual_treatment', 'Not specified'),
            'image_url': sample_images[0]['url'] if sample_images else url_for('static',
                                                                               filename='img/disease-placeholder.jpg'),
            'sample_images': sample_images,
            'last_updated': disease_data.get('created_at')
        })

    except Exception as e:
        print(f"Error getting disease info: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/disease-library')
def disease_library():
    """Public disease library page"""
    try:
        crop = request.args.get('crop', 'corn')

        with get_db_cursor() as cur:
            cur.execute("""
                SELECT 
                    di.id,
                    di.disease_code,
                    di.crop,
                    di.cause,
                    di.symptoms,
                    di.organic_treatment,
                    di.chemical_treatment,
                    di.prevention,
                    di.manual_treatment,
                    di.created_at,
                    (SELECT COUNT(*) FROM disease_samples 
                     WHERE disease_code = di.disease_code AND crop = di.crop) as sample_count,
                    (SELECT id FROM disease_samples 
                     WHERE disease_code = di.disease_code AND crop = di.crop 
                     ORDER BY display_order LIMIT 1) as first_sample_id
                FROM disease_info di
                WHERE di.crop = %s
                ORDER BY di.disease_code
            """, (crop,))

            diseases = []
            for row in cur.fetchall():
                diseases.append({
                    'id': row[0],
                    'disease_code': row[1],
                    'crop': row[2],
                    'cause': row[3],
                    'symptoms': row[4],
                    'organic_treatment': row[5],
                    'chemical_treatment': row[6],
                    'prevention': row[7],
                    'manual_treatment': row[8],
                    'created_at': row[9],
                    'sample_count': row[10],
                    'first_sample_id': row[11]
                })

            # Create image URLs for each disease using the first sample
            for disease in diseases:
                if disease['first_sample_id']:
                    disease['sample_image'] = url_for('get_disease_sample_image', sample_id=disease['first_sample_id'])
                else:
                    disease['sample_image'] = url_for('static', filename='img/disease-placeholder.jpg')

        crop_display = 'Corn' if crop == 'corn' else 'Rice'

        return render_template('disease_library.html',
                               diseases=diseases,
                               crop=crop,
                               crop_display=crop_display)

    except Exception as e:
        print(f"Error in disease_library: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading disease library', 'danger')
        return render_template('disease_library.html', diseases=[], crop='corn', crop_display='Corn')

# ========== API ROUTES FOR SETTINGS ==========

@app.route('/api/settings/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Enable two-factor authentication"""
    user_id = session.get('user_id')
    with get_db_cursor() as cur:
        cur.execute("UPDATE user_settings SET two_factor_enabled = 1 WHERE user_id = %s", (user_id,))
    return jsonify({'success': True})


@app.route('/api/settings/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    user_id = session.get('user_id')
    with get_db_cursor() as cur:
        cur.execute("UPDATE user_settings SET two_factor_enabled = 0 WHERE user_id = %s", (user_id,))
    return jsonify({'success': True})


@app.route('/api/settings/sessions')
@login_required
def get_sessions():
    """Get active user sessions"""
    user_id = session.get('user_id')

    # This is a simplified version - in production, you'd track sessions in a table
    sessions = [
        {
            'session_id': 'current',
            'device': request.user_agent.string[:50] + '...',
            'location': 'Current location',  # You'd get this from request
            'last_active': datetime.now().isoformat(),
            'is_current': True
        }
    ]

    return jsonify({'success': True, 'sessions': sessions})


@app.route('/api/settings/terminate-session/<session_id>', methods=['POST'])
@login_required
def terminate_session(session_id):
    """Terminate a specific session"""
    # In production, you'd invalidate the session
    return jsonify({'success': True})


@app.route('/api/settings/terminate-all-sessions', methods=['POST'])
@login_required
def terminate_all_sessions():
    """Terminate all other sessions"""
    # In production, you'd invalidate all other sessions
    return jsonify({'success': True})


@app.route('/api/settings/export-data')
@login_required
def export_data():
    """Export user data"""
    user_id = session.get('user_id')
    # Generate export URL
    export_url = url_for('download_account_data')
    return jsonify({'success': True, 'url': export_url})


@app.route('/api/settings/clear-history', methods=['POST'])
@login_required
def clear_history():
    """Clear diagnosis history"""
    user_id = session.get('user_id')
    with get_db_cursor() as cur:
        cur.execute("DELETE FROM diagnosis_history WHERE user_id = %s", (user_id,))
    return jsonify({'success': True})


@app.route('/api/settings/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Delete user account"""
    user_id = session.get('user_id')

    # Get profile image to delete
    with get_db_cursor() as cur:
        cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
        user_row = cur.fetchone()
        profile_image = user_row[0] if user_row else None

    # Delete profile image if exists
    if profile_image:
        filepath = os.path.join('static/uploads/profiles', profile_image)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass

    # Delete user data (cascade should handle related records)
    with get_db_cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))

    # Clear session
    session.clear()

    return jsonify({'success': True})


@app.route('/api/settings/reset-settings', methods=['POST'])
@login_required
def reset_settings():
    """Reset all settings to default"""
    user_id = session.get('user_id')
    
    # Delete existing settings
    with get_db_cursor() as cur:
        cur.execute("DELETE FROM user_settings WHERE user_id = %s", (user_id,))

        # Insert default settings
        cur.execute("""
            INSERT INTO user_settings (user_id) VALUES (%s)
        """, (user_id,))

    return jsonify({'success': True})


@app.route('/api/settings/download-data')
@login_required
def download_account_data():
    """Download all user data as JSON"""
    user_id = session.get('user_id')

    with get_db_cursor() as cur:
        # Get user data
        cur.execute(
            "SELECT id, username, email, full_name, phone_number, location, language, bio, created_at FROM users WHERE id = %s",
            (user_id,))
        user_row = cur.fetchone()
        user_data = {
            'id': user_row[0],
            'username': user_row[1],
            'email': user_row[2],
            'full_name': user_row[3],
            'phone_number': user_row[4],
            'location': user_row[5],
            'language': user_row[6],
            'bio': user_row[7],
            'created_at': user_row[8].isoformat() if user_row[8] else None
        }

        # Get diagnosis history (without images to keep file size manageable)
        cur.execute("""
            SELECT id, crop, disease_detected, confidence, created_at, 
                   expert_answers, expert_summary, final_confidence_level
            FROM diagnosis_history 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))
        
        diagnoses = []
        for row in cur.fetchall():
            diagnoses.append({
                'id': row[0],
                'crop': row[1],
                'disease_detected': row[2],
                'confidence': row[3],
                'created_at': row[4].isoformat() if row[4] else None,
                'expert_answers': row[5],
                'expert_summary': row[6],
                'final_confidence_level': row[7]
            })

        # Get settings
        cur.execute("SELECT * FROM user_settings WHERE user_id = %s", (user_id,))
        settings_row = cur.fetchone()
        settings = {}
        if settings_row:
            settings = {
                'email_notifications': settings_row[1],
                'email_updates': settings_row[2],
                'email_newsletter': settings_row[3],
                'email_promotions': settings_row[4],
                'app_notifications': settings_row[5],
                'app_security': settings_row[6],
                'app_reminders': settings_row[7],
                'frequency': settings_row[8],
                'profile_public': settings_row[9],
                'show_diagnosis': settings_row[10],
                'data_collection': settings_row[11],
                'theme': settings_row[12],
                'density': settings_row[13],
                'auto_save': settings_row[14],
                'show_tips': settings_row[15],
                'detailed_results': settings_row[16],
                'quick_analysis': settings_row[17],
                'default_crop': settings_row[18],
                'measurement_unit': settings_row[19]
            }

    # Combine all data
    export_data = {
        'user': user_data,
        'diagnoses': diagnoses,
        'settings': settings,
        'export_date': datetime.now().isoformat()
    }

    # Create JSON response for download
    response = make_response(json.dumps(export_data, indent=2, default=str))
    response.headers['Content-Type'] = 'application/json'
    response.headers[
        'Content-Disposition'] = f'attachment; filename=agriaid_data_{datetime.now().strftime("%Y%m%d")}.json'

    return response

@app.route("/debug-pool")
def debug_pool():
    """Debug connection pool status"""
    try:
        from db_config import get_pool_info

        pool_info = get_pool_info()

        return jsonify({
            "success": True,
            "debug_info": pool_info,
            "message": "Connection pool debug information"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        })


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)