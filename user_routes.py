# user_routes.py (import this in your main app.py)
import json

from flask import render_template, request, session, redirect, url_for, flash, jsonify, Response, make_response, \
    send_file

from db_config import get_db_cursor, get_db_cursor_readonly, get_db, return_db
from auth import hash_password, check_password, validate_email, validate_password, login_required
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from datetime import time as datetime_time
import csv
from io import StringIO

from functools import wraps

# Re-define decorators here since they're used throughout
def login_required(f):
    """Require login for route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next_url'] = request.url
            if request.is_json:
                return jsonify({'success': False, 'message': 'Login required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Require admin privileges for route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_type') != 'admin':
            if request.is_json:
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def expert_required(f):
    """Require expert privileges for route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_type') not in ['expert', 'admin']:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Expert access required'}), 403
            flash('Access denied. Expert privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename, app_config):
    """Check if file extension is allowed"""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app_config['ALLOWED_EXTENSIONS']

def register_user_routes(app):
    def days_since_filter(date):
        """Return number of days since given date"""
        if not date:
            return 0
        delta = datetime.now() - date
        return delta.days

    def get_pending_count():
        """Get count of diagnoses pending review"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) as count 
                    FROM diagnosis_history 
                    WHERE expert_review_status = 'pending' OR expert_review_status IS NULL
                """)
                result = cur.fetchone()
                return result[0] if result else 0
        except Exception as e:
            print(f"Error getting pending count: {e}")
            return 0

    # ========== AUTHENTICATION ROUTES ==========

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """User registration"""
        try:
            # If user is already logged in, redirect them
            if 'user_id' in session:
                next_url = request.args.get('redirect') or url_for('dashboard')
                return redirect(next_url)

            # Get redirect parameter
            redirect_to = request.args.get('redirect', '')

            if request.method == "POST":
                username = request.form.get('username')
                email = request.form.get('email')
                password = request.form.get('password')
                confirm_password = request.form.get('confirm_password')
                full_name = request.form.get('full_name')
                user_type = request.form.get('user_type', 'farmer')
                phone = request.form.get('phone')
                location = request.form.get('location')

                # Get redirect from form
                redirect_after = request.form.get('redirect') or redirect_to

                # Validation
                if password != confirm_password:
                    flash('Passwords do not match!', 'danger')
                    return render_template("register.html", redirect_to=redirect_after)

                valid, message = validate_password(password)
                if not valid:
                    flash(message, 'danger')
                    return render_template("register.html", redirect_to=redirect_after)

                if not validate_email(email):
                    flash('Invalid email address!', 'danger')
                    return render_template("register.html", redirect_to=redirect_after)

                with get_db_cursor() as cur:
                    # Check if user exists
                    cur.execute("SELECT id FROM users WHERE username = %s OR email = %s",
                                (username, email))
                    if cur.fetchone():
                        flash('Username or email already exists!', 'danger')
                        return render_template("register.html", redirect_to=redirect_after)

                    # Create user
                    password_hash = hash_password(password)
                    cur.execute("""
                        INSERT INTO users (username, email, password_hash, full_name, 
                                          user_type, phone_number, location)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (username, email, password_hash, full_name, user_type, phone, location))

                    user_id = cur.fetchone()[0]

                    # Create default settings
                    try:
                        cur.execute("""
                            INSERT INTO user_settings (user_id) VALUES (%s)
                        """, (user_id,))
                    except:
                        pass  # Settings table might not exist

                    # Create subscription if newsletter is checked
                    newsletter = request.form.get('newsletter') == 'on'
                    if newsletter:
                        try:
                            cur.execute("""
                                INSERT INTO user_subscriptions (user_id, newsletter) 
                                VALUES (%s, TRUE)
                            """, (user_id,))
                        except:
                            pass  # Subscriptions table might not exist

                # Auto-login after registration
                session['user_id'] = user_id
                session['username'] = username
                session['email'] = email
                session['user_type'] = user_type
                session['full_name'] = full_name

                flash('Registration successful! Welcome to AgriAId', 'success')

                # Redirect to intended page or dashboard
                if redirect_after:
                    print(f"✅ Registration successful, redirecting to: {redirect_after}")
                    return redirect(redirect_after)
                else:
                    return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"Registration error: {e}")
            import traceback
            traceback.print_exc()
            flash('Registration failed. Please try again.', 'danger')
            return render_template("register.html", redirect_to=redirect_to)

        # GET request - show registration form
        return render_template("register.html", redirect_to=redirect_to)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User login"""
        try:
            # If already logged in, redirect based on role
            if 'user_id' in session:
                if session.get('user_type') == 'admin':
                    print("🔄 Already logged in as admin, redirecting to admin dashboard")
                    return redirect(url_for('admin_dashboard'))
                elif session.get('user_type') == 'expert':
                    print("🔄 Already logged in as expert, redirecting to expert dashboard")
                    return redirect(url_for('expert_dashboard'))
                else:
                    return redirect(url_for('dashboard'))

            # Handle POST request
            if request.method == "POST":
                username = request.form.get('username')
                password = request.form.get('password')
                remember = request.form.get('remember') == 'on'

                print(f"🔐 Login attempt for: {username}")

                # Get user
                with get_db_cursor() as cur:
                    cur.execute("""
                        SELECT id, username, email, password_hash, user_type, 
                               full_name, is_active, profile_image
                        FROM users 
                        WHERE username = %s OR email = %s
                    """, (username, username))

                    user_row = cur.fetchone()

                if user_row:
                    user = {
                        'id': user_row[0],
                        'username': user_row[1],
                        'email': user_row[2],
                        'password_hash': user_row[3],
                        'user_type': user_row[4],
                        'full_name': user_row[5],
                        'is_active': user_row[6],
                        'profile_image': user_row[7]
                    }
                    print(f"✅ User found: {user['username']}, Type: {user['user_type']}, Active: {user['is_active']}")
                else:
                    print(f"❌ User not found: {username}")
                    user = None

                if user and check_password(password, user['password_hash']):
                    if not user['is_active']:
                        flash('Account is deactivated. Contact administrator.', 'danger')
                        return render_template("login.html")

                    # Set session
                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['email'] = user['email']
                    session['user_type'] = user['user_type']
                    session['full_name'] = user['full_name']
                    session['profile_image'] = user['profile_image']
                    session.permanent = True

                    print(f"✅ Session set: user_type={session['user_type']}")

                    # Update last login
                    try:
                        db = get_db()
                        cur = db.cursor()
                        cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))
                        db.commit()
                        return_db(db)
                    except:
                        pass

                    flash(f'Welcome back, {user["username"]}!', 'success')

                    # Check for redirect in this order:
                    # 1. Session saved URL
                    if session.get('next_url'):
                        next_url = session.pop('next_url')
                        return redirect(next_url)

                    # 2. Form redirect
                    if request.form.get('redirect'):
                        return redirect(request.form.get('redirect'))

                    # 3. URL parameter redirect
                    if request.args.get('redirect'):
                        return redirect(request.args.get('redirect'))

                    # 4. Role-based redirect
                    if user['user_type'] == 'admin':
                        print("🚀 Redirecting to ADMIN DASHBOARD")
                        return redirect(url_for('admin_dashboard'))
                    elif user['user_type'] == 'expert':
                        print("🚀 Redirecting to EXPERT DASHBOARD")
                        return redirect(url_for('expert_dashboard'))
                    else:
                        print("🚀 Redirecting to FARMER DASHBOARD")
                        return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password!', 'danger')

            # GET request - show login form
            return render_template("login.html")

        except Exception as e:
            print(f"❌ Login error: {e}")
            import traceback
            traceback.print_exc()
            flash('Login failed. Please try again.', 'danger')
            return render_template("login.html")

    @app.route("/logout")
    def logout():
        """User logout"""
        session.clear()
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))

    # ========== DASHBOARD & PROFILE ==========

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """User dashboard"""
        user_id = session['user_id']

        try:
            with get_db_cursor() as cur:
                # Get user stats - using PostgreSQL syntax
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_diagnoses,
                        COUNT(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 END) as today_diagnoses,
                        AVG(confidence) as avg_confidence
                    FROM diagnosis_history 
                    WHERE user_id = %s
                """, (user_id,))
                stats_row = cur.fetchone()
                
                if stats_row:
                    stats = {
                        'total_diagnoses': stats_row[0] or 0,
                        'today_diagnoses': stats_row[1] or 0,
                        'avg_confidence': round(stats_row[2] or 0, 1)
                    }
                else:
                    stats = {'total_diagnoses': 0, 'today_diagnoses': 0, 'avg_confidence': 0}

                # Get saved count
                saved_count = 0
                try:
                    cur.execute("""
                        SELECT COUNT(*) as saved_count
                        FROM saved_diagnoses 
                        WHERE user_id = %s
                    """, (user_id,))
                    saved_result = cur.fetchone()
                    saved_count = saved_result[0] if saved_result else 0
                except:
                    print("Note: saved_diagnoses table doesn't exist")

                # Get recent diagnoses
                cur.execute("""
                    SELECT id, crop, disease_detected, confidence, 
                           created_at as diagnosis_date
                    FROM diagnosis_history 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 5
                """, (user_id,))
                
                recent_diagnoses = []
                for row in cur.fetchall():
                    recent_diagnoses.append({
                        'id': row[0],
                        'crop': row[1],
                        'disease_detected': row[2],
                        'confidence': row[3],
                        'diagnosis_date': row[4]
                    })

                # Get top diseases
                cur.execute("""
                    SELECT disease_detected, COUNT(*) as count
                    FROM diagnosis_history 
                    WHERE user_id = %s 
                    GROUP BY disease_detected 
                    ORDER BY count DESC 
                    LIMIT 5
                """, (user_id,))
                
                top_diseases = []
                for row in cur.fetchall():
                    top_diseases.append({
                        'disease_detected': row[0],
                        'count': row[1]
                    })

            return render_template("dashboard.html",
                                   stats=stats,
                                   recent_diagnoses=recent_diagnoses,
                                   top_diseases=top_diseases,
                                   saved_count=saved_count)

        except Exception as e:
            print(f"Dashboard error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading dashboard', 'danger')
            return redirect(url_for('upload_image'))

    @app.route("/profile")
    @login_required
    def profile():
        """User profile page"""
        user_id = session['user_id']

        try:
            with get_db_cursor() as cur:
                # Get user data
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                user_row = cur.fetchone()
                
                if not user_row:
                    flash('User not found', 'danger')
                    return redirect(url_for('dashboard'))
                
                # Convert to dictionary with column names (adjust indices as needed)
                user = {
                    'id': user_row[0],
                    'username': user_row[1],
                    'email': user_row[2],
                    'password_hash': user_row[3],
                    'full_name': user_row[4],
                    'user_type': user_row[5],
                    'phone_number': user_row[6],
                    'location': user_row[7],
                    'profile_image': user_row[8],
                    'bio': user_row[9],
                    'is_active': user_row[10],
                    'created_at': user_row[11],
                    'last_login': user_row[12],
                    'updated_at': user_row[13],
                    'language': user_row[14] if len(user_row) > 14 else None
                }

                # Get stats - using PostgreSQL syntax
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_diagnosis,
                        (SELECT COUNT(*) FROM saved_diagnoses WHERE user_id = %s) as saved_items,
                        EXTRACT(DAY FROM (NOW() - MIN(created_at))) as days_active
                    FROM diagnosis_history 
                    WHERE user_id = %s
                """, (user_id, user_id))
                stats_row = cur.fetchone()
                
                stats = {
                    'total_diagnosis': stats_row[0] if stats_row else 0,
                    'saved_items': stats_row[1] if stats_row else 0,
                    'days_active': int(stats_row[2]) if stats_row and stats_row[2] else 0
                }

                # Get recent activity
                cur.execute("""
                    (SELECT 
                        'diagnosis' as type,
                        CONCAT('Diagnosed ', disease_detected) as title,
                        CONCAT('Crop: ', crop) as description,
                        created_at as time,
                        CONCAT('/history/', id) as link
                    FROM diagnosis_history 
                    WHERE user_id = %s)
                    UNION ALL
                    (SELECT 
                        'save' as type,
                        CONCAT('Saved ', disease_detected) as title,
                        'Saved diagnosis for later' as description,
                        sd.created_at as time,
                        CONCAT('/history/', dh.id) as link
                    FROM saved_diagnoses sd
                    JOIN diagnosis_history dh ON sd.diagnosis_id = dh.id
                    WHERE sd.user_id = %s)
                    ORDER BY time DESC
                    LIMIT 10
                """, (user_id, user_id))
                
                recent_activity = []
                for row in cur.fetchall():
                    activity = {
                        'type': row[0],
                        'title': row[1],
                        'description': row[2],
                        'time': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else None,
                        'link': row[4]
                    }
                    recent_activity.append(activity)

                # Get crop expertise
                cur.execute("""
                    SELECT 
                        crop as name,
                        COUNT(*) as diagnosis_count,
                        ROUND(COUNT(*) * 100.0 / NULLIF(SUM(COUNT(*)) OVER(), 0), 1) as percentage
                    FROM diagnosis_history 
                    WHERE user_id = %s AND crop IS NOT NULL
                    GROUP BY crop
                    ORDER BY diagnosis_count DESC
                    LIMIT 6
                """, (user_id,))
                
                crop_expertise = []
                for row in cur.fetchall():
                    crop_expertise.append({
                        'name': row[0],
                        'diagnosis_count': row[1],
                        'percentage': row[2]
                    })

                # Get common diseases
                cur.execute("""
                    SELECT 
                        disease_detected as name,
                        crop,
                        COUNT(*) as count,
                        MAX(created_at) as last_detected,
                        ROUND(AVG(confidence), 1) as avg_confidence,
                        ROUND(COUNT(*) * 100.0 / NULLIF(SUM(COUNT(*)) OVER(), 0), 1) as percentage
                    FROM diagnosis_history 
                    WHERE user_id = %s
                    GROUP BY disease_detected, crop
                    ORDER BY count DESC
                    LIMIT 5
                """, (user_id,))
                
                common_diseases = []
                for row in cur.fetchall():
                    common_diseases.append({
                        'name': row[0],
                        'crop': row[1],
                        'count': row[2],
                        'last_detected': row[3].strftime('%Y-%m-%d') if row[3] else None,
                        'avg_confidence': row[4],
                        'percentage': row[5]
                    })

            # Calculate profile completion
            completion_items = [
                {'label': 'Profile Picture', 'completed': bool(user.get('profile_image')), 'action': '#'},
                {'label': 'Bio', 'completed': bool(user.get('bio')), 'action': '#'},
                {'label': 'Phone Number', 'completed': bool(user.get('phone_number')), 'action': '/settings'},
                {'label': 'Location', 'completed': bool(user.get('location')), 'action': '/settings'},
                {'label': 'First Diagnosis', 'completed': stats['total_diagnosis'] > 0, 'action': '/upload'},
                {'label': 'Saved Item', 'completed': stats['saved_items'] > 0, 'action': '/history'},
            ]

            completed_count = sum(1 for item in completion_items if item['completed'])
            profile_completion = int((completed_count / len(completion_items)) * 100)

            return render_template("profile.html",
                                   user=user,
                                   stats=stats,
                                   recent_activity=recent_activity,
                                   crop_expertise=crop_expertise,
                                   common_diseases=common_diseases,
                                   completion_items=completion_items,
                                   profile_completion=profile_completion,
                                   badges=[])

        except Exception as e:
            print(f"Profile error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading profile', 'danger')
            return redirect(url_for('dashboard'))

    @app.route("/api/profile/update-bio", methods=["POST"])
    @login_required
    def update_bio():
        """Update user bio"""
        user_id = session['user_id']

        try:
            data = request.get_json()
            bio = data.get('bio', '').strip()

            # Validate length
            if len(bio) > 500:
                return jsonify({'success': False, 'error': 'Bio must be 500 characters or less'}), 400

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE users 
                    SET bio = %s, updated_at = NOW() 
                    WHERE id = %s
                """, (bio, user_id))

            return jsonify({
                'success': True,
                'message': 'Bio updated successfully',
                'bio': bio
            })

        except Exception as e:
            print(f"Update bio error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/api/profile/upload-image", methods=["POST"])
    @login_required
    def upload_profile_image():
        """Upload profile image"""
        user_id = session['user_id']

        try:
            if 'profile_image' not in request.files:
                return jsonify({'success': False, 'error': 'No file uploaded'}), 400

            file = request.files['profile_image']

            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400

            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            if not allowed_file(file.filename, {'ALLOWED_EXTENSIONS': allowed_extensions}):
                return jsonify({'success': False, 'error': 'Invalid file type'}), 400

            # Validate file size (max 2MB)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)

            if file_size > 2 * 1024 * 1024:
                return jsonify({'success': False, 'error': 'File size must be less than 2MB'}), 400

            # Get current user to delete old image
            with get_db_cursor() as cur:
                cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
                user_row = cur.fetchone()
                old_image = user_row[0] if user_row else None

            # Delete old image if exists
            if old_image:
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', old_image)
                if os.path.exists(old_image_path):
                    try:
                        os.remove(old_image_path)
                    except:
                        pass

            # Save new image
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = secure_filename(f"{user_id}_{timestamp}_{file.filename}")

            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles')
            os.makedirs(upload_folder, exist_ok=True)

            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)

            # Update database
            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE users 
                    SET profile_image = %s, updated_at = NOW() 
                    WHERE id = %s
                """, (filename, user_id))

            # Update session
            session['profile_image'] = filename

            return jsonify({
                'success': True,
                'message': 'Profile image updated successfully',
                'image_url': url_for('static', filename=f'uploads/profiles/{filename}')
            })

        except Exception as e:
            print(f"Upload profile image error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/change-password", methods=["POST"])
    @login_required
    def change_password():
        """Change user password"""
        user_id = session['user_id']

        try:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if new_password != confirm_password:
                return jsonify({'success': False, 'message': 'Passwords do not match!'})

            valid, message = validate_password(new_password)
            if not valid:
                return jsonify({'success': False, 'message': message})

            with get_db_cursor() as cur:
                # Get current password hash
                cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
                user_row = cur.fetchone()

                if not user_row or not check_password(current_password, user_row[0]):
                    return jsonify({'success': False, 'message': 'Current password is incorrect!'})

                # Update password
                new_hash = hash_password(new_password)
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                            (new_hash, user_id))

            return jsonify({'success': True, 'message': 'Password changed successfully!'})

        except Exception as e:
            print(f"Password change error: {e}")
            return jsonify({'success': False, 'message': 'Failed to change password!'})

    # ========== HISTORY ROUTES ==========

    @app.route("/history")
    @login_required
    def history():
        """View diagnosis history with pagination and filters"""
        user_id = session['user_id']

        try:
            # Get page number
            page = request.args.get('page', 1, type=int)
            per_page = 10
            offset = (page - 1) * per_page

            # --- GET FILTER VALUES FROM URL ---
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            crops = request.args.get('crops', '').split(',') if request.args.get('crops') else []
            diseases = request.args.get('diseases', '').split(',') if request.args.get('diseases') else []
            saved_only = request.args.get('saved_only') == 'true'

            # --- BUILD MAIN QUERY WITH FILTERS ---
            query = """
                SELECT dh.id, dh.crop, dh.disease_detected, dh.confidence, 
                       dh.symptoms, dh.recommendations, dh.created_at,
                       dh.expert_answers, dh.expert_summary, dh.final_confidence_level,
                       u.username,
                       (SELECT COUNT(*) FROM saved_diagnoses WHERE diagnosis_id = dh.id AND user_id = %s) > 0 as saved
                FROM diagnosis_history dh
                JOIN users u ON dh.user_id = u.id
                WHERE dh.user_id = %s
            """
            params = [user_id, user_id]

            # ADD DATE FILTERS
            if date_from:
                query += " AND DATE(dh.created_at) >= %s"
                params.append(date_from)
            if date_to:
                query += " AND DATE(dh.created_at) <= %s"
                params.append(date_to)

            # ADD CROP FILTERS
            if crops and crops[0] != '':
                placeholders = ', '.join(['%s'] * len(crops))
                query += f" AND dh.crop IN ({placeholders})"
                params.extend(crops)

            # ADD DISEASE FILTERS
            if diseases and diseases[0] != '':
                placeholders = ', '.join(['%s'] * len(diseases))
                query += f" AND dh.disease_detected IN ({placeholders})"
                params.extend(diseases)

            # ADD SAVED ONLY FILTER
            if saved_only:
                query += """
                    AND EXISTS (
                        SELECT 1 FROM saved_diagnoses 
                        WHERE diagnosis_id = dh.id AND user_id = %s
                    )
                """
                params.append(user_id)

            # ADD ORDER BY AND PAGINATION
            query += " ORDER BY dh.created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, offset])

            # EXECUTE QUERY
            diagnoses = []
            with get_db_cursor() as cur:
                cur.execute(query, params)
                for row in cur.fetchall():
                    diagnoses.append({
                        'id': row[0],
                        'crop': row[1],
                        'disease_detected': row[2],
                        'confidence': row[3],
                        'symptoms': row[4],
                        'recommendations': row[5],
                        'created_at': row[6],
                        'expert_answers': row[7],
                        'expert_summary': row[8],
                        'final_confidence_level': row[9],
                        'username': row[10],
                        'saved': row[11]
                    })

            # --- GET TOTAL COUNT FOR PAGINATION ---
            count_query = """
                SELECT COUNT(*) as total
                FROM diagnosis_history dh
                WHERE dh.user_id = %s
            """
            count_params = [user_id]

            if date_from:
                count_query += " AND DATE(dh.created_at) >= %s"
                count_params.append(date_from)
            if date_to:
                count_query += " AND DATE(dh.created_at) <= %s"
                count_params.append(date_to)
            if crops and crops[0] != '':
                placeholders = ', '.join(['%s'] * len(crops))
                count_query += f" AND dh.crop IN ({placeholders})"
                count_params.extend(crops)
            if diseases and diseases[0] != '':
                placeholders = ', '.join(['%s'] * len(diseases))
                count_query += f" AND dh.disease_detected IN ({placeholders})"
                count_params.extend(diseases)
            if saved_only:
                count_query += """
                    AND EXISTS (
                        SELECT 1 FROM saved_diagnoses 
                        WHERE diagnosis_id = dh.id AND user_id = %s
                    )
                """
                count_params.append(user_id)

            with get_db_cursor() as cur:
                cur.execute(count_query, count_params)
                total = cur.fetchone()[0] or 0

            # --- STATS (also filtered) ---
            with get_db_cursor() as cur:
                # Total diagnoses
                cur.execute(count_query, count_params)
                total_diagnoses = cur.fetchone()[0]

                # Monthly diagnoses - using PostgreSQL syntax
                monthly_query = """
                    SELECT COUNT(*) as monthly_diagnoses
                    FROM diagnosis_history dh
                    WHERE dh.user_id = %s
                    AND EXTRACT(YEAR FROM dh.created_at) = EXTRACT(YEAR FROM CURRENT_DATE)
                    AND EXTRACT(MONTH FROM dh.created_at) = EXTRACT(MONTH FROM CURRENT_DATE)
                """
                monthly_params = [user_id]
                if date_from:
                    monthly_query += " AND DATE(dh.created_at) >= %s"
                    monthly_params.append(date_from)
                if date_to:
                    monthly_query += " AND DATE(dh.created_at) <= %s"
                    monthly_params.append(date_to)
                if crops and crops[0] != '':
                    placeholders = ', '.join(['%s'] * len(crops))
                    monthly_query += f" AND dh.crop IN ({placeholders})"
                    monthly_params.extend(crops)
                if diseases and diseases[0] != '':
                    placeholders = ', '.join(['%s'] * len(diseases))
                    monthly_query += f" AND dh.disease_detected IN ({placeholders})"
                    monthly_params.extend(diseases)

                cur.execute(monthly_query, monthly_params)
                monthly_diagnoses = cur.fetchone()[0] or 0

                # Average confidence
                cur.execute("""
                    SELECT COALESCE(AVG(confidence), 0) as avg_confidence
                    FROM diagnosis_history dh
                    WHERE dh.user_id = %s
                """, (user_id,))
                avg_confidence = round(cur.fetchone()[0], 1)

                # Saved count
                cur.execute("""
                    SELECT COUNT(*) as saved_count
                    FROM saved_diagnoses
                    WHERE user_id = %s
                """, (user_id,))
                saved_count = cur.fetchone()[0] or 0

                # Get available crops for filter dropdown
                cur.execute("""
                    SELECT DISTINCT crop 
                    FROM diagnosis_history 
                    WHERE user_id = %s AND crop IS NOT NULL
                    ORDER BY crop
                """, (user_id,))
                available_crops = [row[0] for row in cur.fetchall()]

                # Get available diseases for filter dropdown
                cur.execute("""
                    SELECT DISTINCT disease_detected 
                    FROM diagnosis_history 
                    WHERE user_id = %s AND disease_detected IS NOT NULL
                    ORDER BY disease_detected
                """, (user_id,))
                available_diseases = [row[0] for row in cur.fetchall()]

            # --- PAGINATION OBJECT ---
            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page if total > 0 else 1,
                'has_prev': page > 1,
                'has_next': page * per_page < total,
                'prev_num': page - 1 if page > 1 else None,
                'next_num': page + 1 if page * per_page < total else None,
                'iter_pages': lambda: range(max(1, page - 2), min((total + per_page - 1) // per_page, page + 3) + 1)
            }

            # Build query string for pagination links
            query_string = ''
            for key in request.args:
                if key != 'page':
                    query_string += f'&{key}={request.args[key]}'

            return render_template("history.html",
                                   diagnoses=diagnoses,
                                   pagination=pagination,
                                   total_diagnoses=total_diagnoses,
                                   monthly_diagnoses=monthly_diagnoses,
                                   avg_confidence=avg_confidence,
                                   saved_count=saved_count,
                                   available_crops=available_crops,
                                   available_diseases=available_diseases,
                                   query_string=query_string,
                                   date_from=date_from,
                                   date_to=date_to,
                                   selected_crops=crops if crops and crops[0] != '' else [],
                                   selected_diseases=diseases if diseases and diseases[0] != '' else [],
                                   saved_only=saved_only)

        except Exception as e:
            print(f"Error in history route: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading history', 'danger')
            return redirect(url_for('dashboard'))

    @app.route('/diagnosis/<int:diagnosis_id>')
    @login_required
    def view_diagnosis(diagnosis_id):
        """View a specific diagnosis"""
        try:
            user_id = session.get('user_id')

            if not user_id:
                flash('Please log in first', 'warning')
                return redirect(url_for('login'))

            print(f"🔍 Viewing diagnosis {diagnosis_id} for user {user_id}")

            with get_db_cursor() as cur:
                # Get diagnosis details
                cur.execute("""
                    SELECT id, user_id, crop, disease_detected, confidence,
                           symptoms, recommendations, created_at,
                           expert_answers, expert_summary, final_confidence_level
                    FROM diagnosis_history 
                    WHERE id = %s AND user_id = %s
                """, (diagnosis_id, user_id))

                diagnosis_row = cur.fetchone()

                if not diagnosis_row:
                    flash('Diagnosis not found', 'danger')
                    return redirect(url_for('my_diagnoses'))

                # Convert to dict
                diagnosis = {
                    'id': diagnosis_row[0],
                    'user_id': diagnosis_row[1],
                    'crop': diagnosis_row[2],
                    'disease_detected': diagnosis_row[3],
                    'confidence': diagnosis_row[4],
                    'symptoms': diagnosis_row[5],
                    'recommendations': diagnosis_row[6],
                    'created_at': diagnosis_row[7],
                    'expert_answers': diagnosis_row[8],
                    'expert_summary': diagnosis_row[9],
                    'final_confidence_level': diagnosis_row[10] or 'AI Only'
                }

            # Parse JSON fields if they exist
            if diagnosis.get('expert_answers'):
                try:
                    if isinstance(diagnosis['expert_answers'], str):
                        diagnosis['expert_answers'] = json.loads(diagnosis['expert_answers'])
                except:
                    diagnosis['expert_answers'] = []

            if diagnosis.get('expert_summary'):
                try:
                    if isinstance(diagnosis['expert_summary'], str):
                        diagnosis['expert_summary'] = json.loads(diagnosis['expert_summary'])
                except:
                    diagnosis['expert_summary'] = {}

            # Create a result dictionary
            result = {
                'id': diagnosis['id'],
                'disease': diagnosis['disease_detected'],
                'crop': diagnosis['crop'],
                'confidence': diagnosis['confidence'],
                'symptoms': diagnosis['symptoms'],
                'recommendations': diagnosis['recommendations'],
                'created_at': diagnosis['created_at'],
                'final_confidence_level': diagnosis.get('final_confidence_level', 'AI Only'),
                'expert_answers': diagnosis.get('expert_answers', []),
                'expert_summary': diagnosis.get('expert_summary', {})
            }

            return render_template('diagnosis_results.html', result=result)

        except Exception as e:
            print(f"Error in view_diagnosis: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading diagnosis', 'danger')
            return redirect(url_for('my_diagnoses'))

    @app.route("/api/save-diagnosis/<int:diagnosis_id>", methods=["POST"])
    @login_required
    def save_diagnosis(diagnosis_id):
        """Save/unsave a diagnosis"""
        user_id = session['user_id']

        try:
            action = request.json.get('action', 'save')

            with get_db_cursor() as cur:
                if action == 'save':
                    notes = request.json.get('notes', '')
                    cur.execute("""
                        INSERT INTO saved_diagnoses (user_id, diagnosis_id, notes)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (user_id, diagnosis_id) DO NOTHING
                    """, (user_id, diagnosis_id, notes))
                    message = 'Diagnosis saved!'
                else:
                    cur.execute("""
                        DELETE FROM saved_diagnoses 
                        WHERE user_id = %s AND diagnosis_id = %s
                    """, (user_id, diagnosis_id))
                    message = 'Diagnosis removed from saved!'

            return jsonify({'success': True, 'message': message})

        except Exception as e:
            print(f"Save diagnosis error: {e}")
            return jsonify({'success': False, 'message': 'Operation failed!'})

    @app.route("/saved")
    @login_required
    def saved_diagnoses():
        """View saved diagnoses"""
        user_id = session['user_id']

        try:
            with get_db_cursor() as cur:
                # Get saved diagnoses
                cur.execute("""
                    SELECT sd.id, sd.user_id, sd.crop, sd.disease, sd.confidence,
                           sd.symptoms, sd.recommendations, sd.status, sd.created_at,
                           dh.image
                    FROM saved_diagnoses sd
                    LEFT JOIN diagnosis_history dh ON sd.id = dh.id
                    WHERE sd.user_id = %s
                    ORDER BY sd.created_at DESC
                """, (user_id,))
                
                saved_diagnoses = []
                for row in cur.fetchall():
                    saved_diagnoses.append({
                        'id': row[0],
                        'user_id': row[1],
                        'crop': row[2],
                        'disease': row[3],
                        'confidence': row[4],
                        'symptoms': row[5],
                        'recommendations': row[6],
                        'status': row[7],
                        'created_at': row[8],
                        'image': row[9]
                    })

            # --- CALCULATE STATS ---
            total_saved = len(saved_diagnoses)

            # Unique diseases count
            unique_diseases = len(set([d['disease'] for d in saved_diagnoses if d.get('disease')]))

            # Unique crops count
            unique_crops = len(set([d['crop'] for d in saved_diagnoses if d.get('crop')]))

            # Average confidence
            if saved_diagnoses:
                confidences = [d['confidence'] for d in saved_diagnoses if d.get('confidence')]
                avg_confidence = round(sum(confidences) / len(confidences), 1) if confidences else 0
            else:
                avg_confidence = 0

            # Get unique crops for filter dropdown
            crops = sorted(list(set([d['crop'] for d in saved_diagnoses if d.get('crop')])))

            return render_template("saved.html",
                                   saved_diagnoses=saved_diagnoses,
                                   unique_diseases=unique_diseases,
                                   unique_crops=unique_crops,
                                   avg_confidence=avg_confidence,
                                   crops=crops)

        except Exception as e:
            print(f"Saved diagnoses error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading saved diagnoses', 'danger')
            return redirect(url_for('dashboard'))

    @app.route("/api/diagnosis/<int:diagnosis_id>", methods=["DELETE"])
    @login_required
    def delete_diagnosis(diagnosis_id):
        """Delete a diagnosis"""
        user_id = session['user_id']

        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    DELETE FROM diagnosis_history 
                    WHERE id = %s AND user_id = %s
                """, (diagnosis_id, user_id))

            return jsonify({'success': True})

        except Exception as e:
            print(f"Delete error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/api/diagnosis/delete-all", methods=["DELETE"])
    @login_required
    def delete_all_diagnoses():
        """Delete all diagnoses for current user"""
        user_id = session['user_id']

        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    DELETE FROM diagnosis_history
                    WHERE user_id = %s
                """, (user_id,))
                deleted_count = cur.rowcount

            return jsonify({
                'success': True,
                'message': f'Successfully deleted {deleted_count} diagnoses'
            })

        except Exception as e:
            print(f"Delete all error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/diagnosis/<int:diagnosis_id>/toggle-save', methods=['POST'])
    @login_required
    def toggle_save_diagnosis(diagnosis_id):
        """Toggle save status of a diagnosis"""
        try:
            user_id = session['user_id']

            with get_db_cursor() as cur:
                # Check if already saved
                cur.execute("""
                    SELECT id FROM saved_diagnoses 
                    WHERE user_id = %s AND id = %s
                """, (user_id, diagnosis_id))

                existing = cur.fetchone()

                if existing:
                    # Remove from saved
                    cur.execute("""
                        DELETE FROM saved_diagnoses 
                        WHERE user_id = %s AND id = %s
                    """, (user_id, diagnosis_id))
                    saved = False
                    message = "Diagnosis removed from saved"
                else:
                    # Get diagnosis details from history
                    cur.execute("""
                        SELECT crop, disease_detected, confidence, 
                               symptoms, recommendations, created_at,
                               final_confidence_level
                        FROM diagnosis_history 
                        WHERE id = %s
                    """, (diagnosis_id,))
                    diagnosis = cur.fetchone()

                    if not diagnosis:
                        return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

                    # Save to saved_diagnoses
                    cur.execute("""
                        INSERT INTO saved_diagnoses 
                        (id, user_id, crop, disease, confidence, 
                         symptoms, recommendations, status, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        diagnosis_id,
                        user_id,
                        diagnosis[0],  # crop
                        diagnosis[1],  # disease_detected
                        diagnosis[2],  # confidence
                        diagnosis[3],  # symptoms
                        diagnosis[4],  # recommendations
                        diagnosis[6] or 'AI Only',  # final_confidence_level
                        diagnosis[5]   # created_at
                    ))
                    saved = True
                    message = "Diagnosis saved successfully"

            return jsonify({
                'success': True,
                'saved': saved,
                'message': message
            })

        except Exception as e:
            print(f"Error toggling save: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/check-saved-status')
    @login_required
    def check_saved_status():
        """Check which diagnoses are saved"""
        try:
            user_id = session['user_id']
            ids = request.args.get('ids', '').split(',')

            if not ids or ids[0] == '':
                return jsonify({'saved': []})

            # Convert to integers and filter out empty strings
            ids = [int(id) for id in ids if id.strip()]

            if not ids:
                return jsonify({'saved': []})

            placeholders = ','.join(['%s'] * len(ids))
            with get_db_cursor() as cur:
                cur.execute(f"""
                    SELECT id FROM saved_diagnoses 
                    WHERE user_id = %s AND id IN ({placeholders})
                """, [user_id] + ids)

                saved = [row[0] for row in cur.fetchall()]

            return jsonify({'saved': saved})

        except Exception as e:
            print(f"Error checking saved status: {e}")
            return jsonify({'saved': []})

    # ========== FEEDBACK ROUTES ==========

    @app.route("/feedback", methods=["GET"])
    @login_required
    def feedback():
        """Show feedback page with user's previous feedback"""
        user_id = session.get('user_id')
        user_feedback = []

        try:
            if user_id:
                with get_db_cursor() as cur:
                    # Check if table exists
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_name = 'feedback'
                        )
                    """)
                    table_exists = cur.fetchone()[0]
                    
                    if table_exists:
                        cur.execute("""
                            SELECT id, user_id, name, email, feedback_type, 
                                   subject, message, image_path, status, 
                                   admin_response, created_at
                            FROM feedback 
                            WHERE user_id = %s 
                            ORDER BY created_at DESC 
                            LIMIT 10
                        """, (user_id,))
                        
                        for row in cur.fetchall():
                            user_feedback.append({
                                'id': row[0],
                                'user_id': row[1],
                                'name': row[2],
                                'email': row[3],
                                'feedback_type': row[4],
                                'subject': row[5],
                                'message': row[6],
                                'image_path': row[7],
                                'status': row[8],
                                'admin_response': row[9],
                                'created_at': row[10]
                            })

        except Exception as e:
            print(f"Error loading user feedback: {e}")

        return render_template('feedback.html', user_feedback=user_feedback)

    @app.route('/feedback')
    def feedback_page():
        """Display feedback form and user's previous feedback"""
        user_feedback = []

        # If user is logged in, get their previous feedback
        if session.get('user_id'):
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT id, user_id, name, email, feedback_type, 
                           subject, message, image_path, status, 
                           admin_response, created_at
                    FROM feedback 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """, (session['user_id'],))
                
                for row in cur.fetchall():
                    user_feedback.append({
                        'id': row[0],
                        'user_id': row[1],
                        'name': row[2],
                        'email': row[3],
                        'feedback_type': row[4],
                        'subject': row[5],
                        'message': row[6],
                        'image_path': row[7],
                        'status': row[8],
                        'admin_response': row[9],
                        'created_at': row[10]
                    })

        return render_template('feedback.html', user_feedback=user_feedback)

    @app.route('/submit-feedback', methods=['POST'])
    @login_required
    def submit_feedback():
        """Handle feedback submission - user must be logged in"""
        try:
            # Get form data
            feedback_type = request.form.get('feedback_type')
            subject = request.form.get('subject')
            message = request.form.get('message')

            # Validate required fields
            if not all([feedback_type, subject, message]):
                flash('Please fill in all required fields', 'error')
                return redirect(url_for('feedback_page'))

            # Check if user wants to be anonymous
            anonymous = request.form.get('anonymous') == 'on'

            # Set name/email based on anonymous preference
            if anonymous:
                name = 'Anonymous User'
                email = None
                user_id = None
            else:
                name = session.get('username', 'User')
                email = session.get('email')
                user_id = session.get('user_id')

            # Handle image upload
            image_file = None
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename:
                    # Validate file type
                    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                        # Check file size (max 5MB)
                        file.seek(0, 2)
                        size = file.tell()
                        file.seek(0)

                        if size <= 5 * 1024 * 1024:
                            # Generate unique filename
                            import uuid
                            from werkzeug.utils import secure_filename

                            filename = str(uuid.uuid4()) + '_' + secure_filename(file.filename)
                            file_path = os.path.join('static/uploads/feedback', filename)

                            # Ensure directory exists
                            os.makedirs('static/uploads/feedback', exist_ok=True)

                            file.save(file_path)
                            image_file = filename

            # Insert into database
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO feedback 
                    (user_id, name, email, feedback_type, subject, message, image_path, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    user_id,
                    name,
                    email,
                    feedback_type,
                    subject,
                    message,
                    image_file,
                    'pending'
                ))

            flash('Thank you for your feedback! We appreciate your input.', 'success')
            return redirect(url_for('feedback_page'))

        except Exception as e:
            print(f"Error submitting feedback: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred while submitting your feedback. Please try again.', 'error')
            return redirect(url_for('feedback_page'))

    @app.route('/test-feedback-db')
    @login_required
    def test_feedback_db():
        """Test feedback table structure - PostgreSQL version"""
        try:
            with get_db_cursor() as cur:
                # Check if table exists
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'feedback'
                    )
                """)
                exists = cur.fetchone()[0]
                
                if not exists:
                    return "❌ feedback table does not exist!"

                # Show table structure
                cur.execute("""
                    SELECT column_name, data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_name = 'feedback'
                    ORDER BY ordinal_position
                """)
                columns = cur.fetchall()

                result = "<h3>Feedback Table Structure:</h3><ul>"
                for col in columns:
                    result += f"<li>{col[0]} - {col[1]} (Nullable: {col[2]})</li>"
                result += "</ul>"

                return result

        except Exception as e:
            return f"Error: {e}"

    @app.route('/debug-feedback', methods=['POST'])
    @login_required
    def debug_feedback():
        """Debug endpoint to see form data"""
        print("=" * 50)
        print("DEBUG FEEDBACK RECEIVED")
        print("Form data:", dict(request.form))
        print("Files:", request.files)
        print("Headers:", dict(request.headers))
        print("=" * 50)

        return jsonify({
            'form': dict(request.form),
            'files': [f.filename for f in request.files.values()]
        })

    @app.route("/feedback/<int:diagnosis_id>", methods=["GET", "POST"])
    @login_required
    def diagnosis_feedback(diagnosis_id):
        """Submit feedback for a diagnosis"""
        user_id = session['user_id']

        try:
            # Verify diagnosis belongs to user
            with get_db_cursor() as cur:
                cur.execute("SELECT id FROM diagnosis_history WHERE id = %s AND user_id = %s",
                            (diagnosis_id, user_id))

                if not cur.fetchone():
                    flash('Diagnosis not found!', 'danger')
                    return redirect(url_for('history'))

                if request.method == "POST":
                    rating = request.form.get('rating')
                    accuracy = request.form.get('accuracy')
                    feedback_text = request.form.get('feedback')
                    suggestions = request.form.get('suggestions')

                    cur.execute("""
                        INSERT INTO feedback 
                        (user_id, diagnosis_id, rating, accuracy_rating, 
                         feedback_text, suggestions)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (user_id, diagnosis_id) 
                        DO UPDATE SET
                            rating = EXCLUDED.rating,
                            accuracy_rating = EXCLUDED.accuracy_rating,
                            feedback_text = EXCLUDED.feedback_text,
                            suggestions = EXCLUDED.suggestions,
                            created_at = NOW()
                    """, (user_id, diagnosis_id, rating, accuracy, feedback_text, suggestions))

                    flash('Thank you for your feedback!', 'success')
                    return redirect(url_for('view_diagnosis', diagnosis_id=diagnosis_id))

                # GET request - show feedback form
                cur.execute("SELECT * FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
                diagnosis_row = cur.fetchone()
                
                # Convert to dict (simplified)
                diagnosis = {'id': diagnosis_row[0]} if diagnosis_row else None

            return render_template("feedback_form.html", diagnosis=diagnosis)

        except Exception as e:
            print(f"Feedback error: {e}")
            flash('Failed to submit feedback.', 'danger')
            return redirect(url_for('view_diagnosis', diagnosis_id=diagnosis_id))

    @app.route("/api/feedback/stats")
    @login_required
    def feedback_stats():
        """Get feedback statistics for admin"""
        if session.get('user_type') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403

        try:
            with get_db_cursor() as cur:
                # Overall stats
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_feedback,
                        AVG(rating) as avg_rating,
                        AVG(accuracy_rating) as avg_accuracy,
                        COUNT(DISTINCT user_id) as unique_users
                    FROM feedback
                """)
                stats_row = cur.fetchone()
                
                stats = {
                    'total_feedback': stats_row[0] or 0,
                    'avg_rating': float(stats_row[1]) if stats_row[1] else 0,
                    'avg_accuracy': float(stats_row[2]) if stats_row[2] else 0,
                    'unique_users': stats_row[3] or 0
                }

                # Recent feedback
                cur.execute("""
                    SELECT f.id, f.user_id, f.name, f.email, f.feedback_type,
                           f.subject, f.message, f.status, f.created_at,
                           f.admin_response, u.username
                    FROM feedback f
                    LEFT JOIN users u ON f.user_id = u.id
                    ORDER BY f.created_at DESC
                    LIMIT 10
                """)
                
                recent_feedback = []
                for row in cur.fetchall():
                    recent_feedback.append({
                        'id': row[0],
                        'user_id': row[1],
                        'name': row[2],
                        'email': row[3],
                        'feedback_type': row[4],
                        'subject': row[5],
                        'message': row[6],
                        'status': row[7],
                        'created_at': row[8].isoformat() if row[8] else None,
                        'admin_response': row[9],
                        'username': row[10]
                    })

            return jsonify({
                'stats': stats,
                'recent_feedback': recent_feedback
            })

        except Exception as e:
            print(f"Feedback stats error: {e}")
            return jsonify({'error': str(e)}), 500

    # ========== ADMIN DASHBOARD ROUTES ==========
    @app.route("/admin/dashboard")
    @login_required
    @admin_required
    def admin_dashboard():
        """Admin dashboard"""
        return render_template("admin/dashboard.html")

    @app.route("/admin/users")
    @login_required
    @admin_required
    def admin_users():
        """Admin - User management"""
        return render_template("admin/users.html")

    @app.route("/admin/disease-library")
    @login_required
    @admin_required
    def admin_disease_library():
        """Admin - Disease library management"""
        return render_template("admin/admin_disease_library.html")

    @app.route("/admin/history")
    @login_required
    @admin_required
    def admin_history():
        """Admin - Diagnosis history"""
        return render_template("admin/admin_history.html")

    @app.route("/admin/analytics")
    @login_required
    @admin_required
    def admin_analytics():
        """Admin - Analytics"""
        return render_template("admin/analytics.html")

    @app.route("/admin/settings")
    @login_required
    @admin_required
    def admin_settings():
        """Admin - Settings"""
        return render_template("admin/settings.html")

    @app.route("/admin/feedback")
    @login_required
    @admin_required
    def admin_feedback():
        """Admin - Feedback management"""
        return render_template("admin/feedback.html")

    @app.route("/admin/system-health")
    @login_required
    @admin_required
    def admin_system_health():
        """Admin - System health"""
        return render_template("admin/admin_system_health.html")

    @app.route("/admin/activity-logs")
    @login_required
    @admin_required
    def admin_activity_logs():
        """Admin - Activity logs"""
        return render_template("admin/admin_activity_logs.html")

    @app.route("/admin/diagnoses-history")
    @login_required
    @admin_required
    def admin_diagnoses_history():
        """Admin - Diagnoses history"""
        return render_template("admin/admin_diagnoses_history.html")

    # Return the app
    return app