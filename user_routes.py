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
        """Admin dashboard with comprehensive analytics"""
        try:
            with get_db_cursor() as cur:
                # Get user statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_users,
                        SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
                        SUM(CASE WHEN is_active = FALSE OR is_active IS NULL THEN 1 ELSE 0 END) as inactive_users,
                        SUM(CASE WHEN user_type = 'farmer' THEN 1 ELSE 0 END) as total_farmers,
                        SUM(CASE WHEN user_type = 'expert' THEN 1 ELSE 0 END) as total_experts,
                        SUM(CASE WHEN user_type = 'researcher' THEN 1 ELSE 0 END) as total_researchers,
                        SUM(CASE WHEN user_type = 'student' THEN 1 ELSE 0 END) as total_students,
                        SUM(CASE WHEN user_type = 'admin' THEN 1 ELSE 0 END) as total_admins
                    FROM users
                """)
                stats_row = cur.fetchone()
                
                user_stats = {
                    'total_users': stats_row[0] or 0,
                    'active_users': stats_row[1] or 0,
                    'inactive_users': stats_row[2] or 0,
                    'total_farmers': stats_row[3] or 0,
                    'total_experts': stats_row[4] or 0,
                    'total_researchers': stats_row[5] or 0,
                    'total_students': stats_row[6] or 0,
                    'total_admins': stats_row[7] or 0
                }

                # Active users today
                cur.execute("""
                    SELECT COUNT(DISTINCT user_id) as active_today
                    FROM diagnosis_history
                    WHERE DATE(created_at) = CURRENT_DATE
                """)
                active_today = cur.fetchone()[0] or 0

                # ===== DIAGNOSIS STATISTICS =====
                cur.execute("SELECT COUNT(*) as total FROM diagnosis_history")
                total_diagnoses = cur.fetchone()[0] or 0

                cur.execute("""
                    SELECT COUNT(*) as monthly
                    FROM diagnosis_history
                    WHERE EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) 
                    AND EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM CURRENT_DATE)
                """)
                monthly_diagnoses = cur.fetchone()[0] or 0

                # Average confidence
                cur.execute("""
                    SELECT COALESCE(AVG(confidence), 0) as avg_confidence
                    FROM diagnosis_history
                """)
                avg_confidence = round(cur.fetchone()[0], 1)

                # Top diseases detected
                cur.execute("""
                    SELECT 
                        disease_detected,
                        COUNT(*) as count,
                        AVG(confidence) as avg_confidence
                    FROM diagnosis_history
                    WHERE disease_detected != 'healthy' AND disease_detected IS NOT NULL
                    GROUP BY disease_detected
                    ORDER BY count DESC
                    LIMIT 5
                """)
                
                top_diseases = []
                for row in cur.fetchall():
                    top_diseases.append({
                        'disease_detected': row[0],
                        'count': row[1],
                        'avg_confidence': float(row[2]) if row[2] else 0
                    })

                # Diagnoses by crop
                cur.execute("""
                    SELECT 
                        crop,
                        COUNT(*) as count
                    FROM diagnosis_history
                    WHERE crop IS NOT NULL
                    GROUP BY crop
                    ORDER BY count DESC
                """)
                
                diagnoses_by_crop = []
                for row in cur.fetchall():
                    diagnoses_by_crop.append({
                        'crop': row[0],
                        'count': row[1]
                    })

                # ===== DISEASE INFO STATISTICS =====
                cur.execute("SELECT COUNT(*) as total_diseases FROM disease_info")
                total_diseases = cur.fetchone()[0] or 0

                # Disease distribution by crop from disease_info
                cur.execute("""
                    SELECT 
                        crop,
                        COUNT(*) as disease_count
                    FROM disease_info
                    GROUP BY crop
                    ORDER BY disease_count DESC
                """)
                
                disease_by_crop = []
                for row in cur.fetchall():
                    disease_by_crop.append({
                        'crop': row[0],
                        'disease_count': row[1]
                    })

                # ===== FEEDBACK STATISTICS =====
                # Check if feedback table exists
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'feedback'
                    )
                """)
                feedback_table_exists = cur.fetchone()[0]

                feedback_stats = {'total_feedback': 0, 'pending_feedback': 0, 'resolved_feedback': 0}
                
                if feedback_table_exists:
                    cur.execute("""
                        SELECT 
                            COUNT(*) as total_feedback,
                            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_feedback,
                            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_feedback
                        FROM feedback
                    """)
                    fb_row = cur.fetchone()
                    if fb_row:
                        feedback_stats = {
                            'total_feedback': fb_row[0] or 0,
                            'pending_feedback': fb_row[1] or 0,
                            'resolved_feedback': fb_row[2] or 0
                        }

                # ===== RECENT ACTIVITIES =====
                cur.execute("""
                    SELECT 
                        dh.created_at,
                        u.username,
                        CONCAT('Diagnosed ', dh.disease_detected, ' on ', dh.crop) as action,
                        u.id as user_id
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    ORDER BY dh.created_at DESC
                    LIMIT 10
                """)
                
                recent_activities = []
                for row in cur.fetchall():
                    recent_activities.append({
                        'created_at': row[0],
                        'username': row[1],
                        'action': row[2],
                        'user_id': row[3]
                    })

                # ===== ADD AVATAR COLORS =====
                avatar_colors = [
                    '#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0',
                    '#6610f2', '#6f42c1', '#d63384', '#fd7e14', '#20c997'
                ]

                for i, activity in enumerate(recent_activities):
                    activity['avatar_color'] = avatar_colors[i % len(avatar_colors)]

                # ===== SIDEBAR STATS =====
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = FALSE")
                pending_users = cur.fetchone()[0] or 0

                sidebar_stats = {
                    'pending_users': pending_users,
                    'pending_feedback': feedback_stats['pending_feedback']
                }

                # ===== CONFIDENCE STATS =====
                confidence_stats = {
                    'avg_confidence': avg_confidence
                }

                # ===== ACCURACY STATS =====
                accuracy_stats = {
                    'accuracy_rate': avg_confidence,
                    'total_verified': total_diagnoses,
                    'accurate_detections': int(total_diagnoses * (avg_confidence / 100)) if avg_confidence > 0 else 0
                }

                # ===== SYSTEM HEALTH SCORE =====
                health_score = 0.0
                health_factors = []

                # Factor 1: User engagement (30%)
                if user_stats['total_users'] > 0:
                    engagement_rate = (active_today / user_stats['total_users']) * 100
                    engagement_score = min(30.0, (engagement_rate / 10) * 3)
                    health_factors.append({'factor': 'User Engagement', 'score': round(engagement_score, 1), 'max': 30})
                    health_score += engagement_score

                # Factor 2: Diagnosis activity (30%)
                if total_diagnoses > 0:
                    activity_score = min(30.0, (total_diagnoses / 50) * 15)
                    health_factors.append({'factor': 'Diagnosis Activity', 'score': round(activity_score, 1), 'max': 30})
                    health_score += activity_score

                # Factor 3: Disease coverage (20%)
                if total_diseases > 0:
                    coverage_score = min(20.0, total_diseases * 2)
                    health_factors.append({'factor': 'Disease Coverage', 'score': round(coverage_score, 1), 'max': 20})
                    health_score += coverage_score

                # Factor 4: Feedback response (20%)
                if feedback_stats['total_feedback'] > 0:
                    resolution_rate = (feedback_stats['resolved_feedback'] / feedback_stats['total_feedback']) * 100
                    feedback_score = min(20.0, (resolution_rate / 100) * 20)
                    health_factors.append(
                        {'factor': 'Feedback Resolution', 'score': round(feedback_score, 1), 'max': 20})
                    health_score += feedback_score

                health_score = round(health_score, 1)

            return render_template("admin/dashboard.html",
                                   user_stats=user_stats,
                                   active_today=active_today,
                                   avg_confidence=avg_confidence,
                                   confidence_stats=confidence_stats,
                                   accuracy_stats=accuracy_stats,
                                   total_diagnoses=total_diagnoses,
                                   monthly_diagnoses=monthly_diagnoses,
                                   total_diseases=total_diseases,
                                   disease_by_crop=disease_by_crop,
                                   diagnoses_by_crop=diagnoses_by_crop,
                                   top_diseases=top_diseases,
                                   feedback_stats=feedback_stats,
                                   health_score=health_score,
                                   health_factors=health_factors,
                                   recent_activities=recent_activities,
                                   avatar_colors=avatar_colors,
                                   stats=sidebar_stats,
                                   now=datetime.now())

        except Exception as e:
            print(f"Admin dashboard error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading admin dashboard', 'danger')
            return redirect(url_for('dashboard'))

    # ========== ADMIN USER MANAGEMENT ==========
    @app.route("/admin/users")
    @login_required
    @admin_required
    def admin_users():
        """Admin - User management with CRUD operations"""
        # Initialize default values
        users = []
        stats = {
            'total_users': 0, 'farmers': 0, 'experts': 0, 'researchers': 0,
            'students': 0, 'admins': 0, 'active_today': 0, 'active_users': 0, 'inactive_users': 0
        }
        total_users = 0
        total_pages = 1
        pending_feedback = 0
        pending_diseases = 0
        pending_reviews = 0
        
        try:
            # Get page and filters
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            user_type = request.args.get('type', '')
            status = request.args.get('status', '')
            search = request.args.get('search', '')

            # Build query with filters
            query = "SELECT * FROM users WHERE 1=1"
            count_query = "SELECT COUNT(*) as total FROM users WHERE 1=1"
            params = []
            count_params = []

            if user_type:
                query += " AND user_type = %s"
                count_query += " AND user_type = %s"
                params.append(user_type)
                count_params.append(user_type)

            if status == 'active':
                query += " AND is_active = TRUE"
                count_query += " AND is_active = TRUE"
            elif status == 'inactive':
                query += " AND is_active = FALSE"
                count_query += " AND is_active = FALSE"

            if search:
                query += " AND (username ILIKE %s OR email ILIKE %s OR full_name ILIKE %s)"
                count_query += " AND (username ILIKE %s OR email ILIKE %s OR full_name ILIKE %s)"
                search_param = f"%{search}%"
                params.extend([search_param, search_param, search_param])
                count_params.extend([search_param, search_param, search_param])

            # Get total count
            with get_db_cursor() as cur:
                cur.execute(count_query, count_params)
                total_users = cur.fetchone()[0] or 0
                total_pages = (total_users + per_page - 1) // per_page if total_users > 0 else 1

                # Add pagination
                query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
                pagination_params = params + [per_page, offset]

                cur.execute(query, pagination_params)
                for row in cur.fetchall():
                    users.append({
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'password_hash': row[3],
                        'full_name': row[4],
                        'user_type': row[5],
                        'phone_number': row[6],
                        'location': row[7],
                        'profile_image': row[8],
                        'bio': row[9],
                        'is_active': row[10],
                        'created_at': row[11],
                        'last_login': row[12],
                        'updated_at': row[13],
                        'language': row[14] if len(row) > 14 else None
                    })

            # Get statistics for cards - in a separate transaction
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_users,
                        SUM(CASE WHEN user_type = 'farmer' THEN 1 ELSE 0 END) as farmers,
                        SUM(CASE WHEN user_type = 'expert' THEN 1 ELSE 0 END) as experts,
                        SUM(CASE WHEN user_type = 'researcher' THEN 1 ELSE 0 END) as researchers,
                        SUM(CASE WHEN user_type = 'student' THEN 1 ELSE 0 END) as students,
                        SUM(CASE WHEN user_type = 'admin' THEN 1 ELSE 0 END) as admins,
                        SUM(CASE WHEN DATE(last_login) = CURRENT_DATE THEN 1 ELSE 0 END) as active_today,
                        SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
                        SUM(CASE WHEN is_active = FALSE THEN 1 ELSE 0 END) as inactive_users
                    FROM users
                """)
                stats_row = cur.fetchone()
                if stats_row:
                    stats = {
                        'total_users': stats_row[0] or 0,
                        'farmers': stats_row[1] or 0,
                        'experts': stats_row[2] or 0,
                        'researchers': stats_row[3] or 0,
                        'students': stats_row[4] or 0,
                        'admins': stats_row[5] or 0,
                        'active_today': stats_row[6] or 0,
                        'active_users': stats_row[7] or 0,
                        'inactive_users': stats_row[8] or 0
                    }

            # Get pending counts - in separate try/except blocks so one failure doesn't break everything
            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                    result = cur.fetchone()
                    pending_feedback = result[0] if result else 0
            except Exception as e:
                print(f"Error getting pending feedback count: {e}")
                pending_feedback = 0

            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                    result = cur.fetchone()
                    pending_diseases = result[0] if result else 0
            except Exception:
                pending_diseases = 0

            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                    result = cur.fetchone()
                    pending_reviews = result[0] if result else 0
            except Exception as e:
                print(f"Error getting pending reviews count: {e}")
                pending_reviews = 0

            sidebar_stats = {
                'pending_users': stats['inactive_users'],
                'pending_feedback': pending_feedback,
                'pending_diseases': pending_diseases,
                'pending_reviews': pending_reviews
            }

            # Build filter params for pagination
            filter_params = ''
            if user_type:
                filter_params += f'&type={user_type}'
            if status:
                filter_params += f'&status={status}'
            if search:
                filter_params += f'&search={search}'

            return render_template("admin/users.html",
                                   users=users,
                                   page=page,
                                   total_pages=total_pages,
                                   total_users=total_users,
                                   stats=stats,
                                   sidebar_stats=sidebar_stats,
                                   filter_params=filter_params,
                                   filters={'type': user_type, 'status': status, 'search': search})

        except Exception as e:
            print(f"Admin users error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading users', 'danger')
            return redirect(url_for('admin_dashboard'))

    @app.route("/admin/user/create", methods=["POST"])
    @login_required
    @admin_required
    def admin_create_user():
        """Admin - Create new user"""
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            user_type = request.form.get('user_type')
            phone = request.form.get('phone')
            location = request.form.get('location')

            with get_db_cursor() as cur:
                # Check if user exists
                cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
                if cur.fetchone():
                    flash('Username or email already exists!', 'danger')
                    return redirect(url_for('admin_users'))

                # Create user
                password_hash = hash_password(password)
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, full_name, user_type, 
                                      phone_number, location, is_active, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, NOW())
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

            flash(f'User {username} created successfully!', 'success')

        except Exception as e:
            print(f"Create user error: {e}")
            flash('Error creating user', 'danger')

        return redirect(url_for('admin_users'))

    @app.route("/admin/user/<int:user_id>/update", methods=["POST"])
    @login_required
    @admin_required
    def admin_update_user(user_id):
        """Admin - Update user details"""
        try:
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            location = request.form.get('location')
            user_type = request.form.get('user_type')

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE users 
                    SET full_name = %s, phone_number = %s, location = %s, 
                        user_type = %s, updated_at = NOW()
                    WHERE id = %s
                """, (full_name, phone, location, user_type, user_id))

            flash('User updated successfully!', 'success')

        except Exception as e:
            print(f"Update user error: {e}")
            flash('Error updating user', 'danger')

        return redirect(url_for('admin_users'))

    @app.route("/admin/user/<int:user_id>/toggle-status", methods=["POST"])
    @login_required
    @admin_required
    def admin_toggle_user_status(user_id):
        """Admin - Activate/Deactivate user"""
        try:
            with get_db_cursor() as cur:
                # Get current status
                cur.execute("SELECT username, is_active FROM users WHERE id = %s", (user_id,))
                user_row = cur.fetchone()

                if not user_row:
                    return jsonify({'success': False, 'error': 'User not found'}), 404

                # Toggle status
                new_status = not user_row[1]
                cur.execute("UPDATE users SET is_active = %s, updated_at = NOW() WHERE id = %s",
                            (new_status, user_id))

            return jsonify({'success': True, 'is_active': new_status})

        except Exception as e:
            print(f"Toggle user status error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_delete_user(user_id):
        """Admin - Delete user"""
        try:
            # Don't allow deleting own account
            if user_id == session['user_id']:
                return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

            with get_db_cursor() as cur:
                # Delete user settings first
                try:
                    cur.execute("DELETE FROM user_settings WHERE user_id = %s", (user_id,))
                except:
                    pass

                # Delete user
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))

            return jsonify({'success': True})

        except Exception as e:
            print(f"Delete user error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/api/admin/user/<int:user_id>")
    @login_required
    @admin_required
    def admin_get_user(user_id):
        """API - Get user details"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number, location, profile_image,
                           is_active, created_at, last_login
                    FROM users 
                    WHERE id = %s
                """, (user_id,))

                user_row = cur.fetchone()

                if not user_row:
                    return jsonify({'error': 'User not found'}), 404

                user = {
                    'id': user_row[0],
                    'username': user_row[1],
                    'email': user_row[2],
                    'full_name': user_row[3],
                    'user_type': user_row[4],
                    'phone': user_row[5],
                    'location': user_row[6],
                    'profile_image': user_row[7],
                    'is_active': user_row[8],
                    'created_at': user_row[9].strftime('%Y-%m-%d %H:%M:%S') if user_row[9] else None,
                    'last_login': user_row[10].strftime('%Y-%m-%d %H:%M:%S') if user_row[10] else None
                }

            return jsonify(user)

        except Exception as e:
            print(f"Get user error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route("/admin/users/export")
    @login_required
    @admin_required
    def admin_export_users():
        """Admin - Export users to CSV"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number, location, is_active, created_at, last_login
                    FROM users
                    ORDER BY created_at DESC
                """)

                users = []
                for row in cur.fetchall():
                    users.append({
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'full_name': row[3],
                        'user_type': row[4],
                        'phone_number': row[5],
                        'location': row[6],
                        'is_active': row[7],
                        'created_at': row[8],
                        'last_login': row[9]
                    })

            # Create CSV
            output = StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow(['ID', 'Username', 'Email', 'Full Name', 'User Type',
                             'Phone', 'Location', 'Status', 'Created At', 'Last Login'])

            # Write data
            for user in users:
                writer.writerow([
                    user['id'],
                    user['username'],
                    user['email'],
                    user['full_name'] or '',
                    user['user_type'],
                    user['phone_number'] or '',
                    user['location'] or '',
                    'Active' if user['is_active'] else 'Inactive',
                    user['created_at'].strftime('%Y-%m-%d %H:%M') if user['created_at'] else '',
                    user['last_login'].strftime('%Y-%m-%d %H:%M') if user['last_login'] else ''
                ])

            # Prepare response
            output.seek(0)
            filename = f"users_export_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )

        except Exception as e:
            print(f"Export users error: {e}")
            flash('Error exporting users', 'danger')
            return redirect(url_for('admin_users'))

    # ========== ADMIN FEEDBACK MANAGEMENT ==========
    @app.route('/admin/feedback')
    @login_required
    @admin_required
    def admin_feedback():
        """Admin view to see all feedback"""
        # Initialize default values
        feedback_list = []
        categories = []
        pending_users = 0
        pending_feedback = 0
        pending_diseases = 0
        pending_reviews = 0
        
        try:
            # Get filter parameters
            status = request.args.get('status', '')
            category = request.args.get('category', '')
            search = request.args.get('search', '')

            # Base query for feedback
            query = """
                SELECT f.id, f.user_id, f.name, f.email, f.feedback_type,
                       f.subject, f.message, f.image_path, f.status,
                       f.admin_response, f.created_at,
                       u.username, u.full_name, u.user_type
                FROM feedback f
                LEFT JOIN users u ON f.user_id = u.id
                WHERE 1=1
            """
            params = []

            # Add filters
            if status:
                query += " AND f.status = %s"
                params.append(status)

            if category:
                query += " AND f.feedback_type = %s"
                params.append(category)

            if search:
                query += " AND (f.subject ILIKE %s OR f.message ILIKE %s OR f.name ILIKE %s OR f.email ILIKE %s)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term, search_term])

            query += " ORDER BY f.created_at DESC"

            # Get feedback data in its own transaction
            with get_db_cursor() as cur:
                cur.execute(query, params)
                for row in cur.fetchall():
                    feedback_list.append({
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
                        'created_at': row[10],
                        'username': row[11],
                        'full_name': row[12],
                        'user_type': row[13]
                    })

            # Get unique categories in its own transaction
            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT DISTINCT feedback_type FROM feedback WHERE feedback_type IS NOT NULL")
                    categories = [row[0] for row in cur.fetchall()]
            except Exception as e:
                print(f"Error getting categories: {e}")
                categories = []

            # Get sidebar stats - each in its own transaction
            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = FALSE")
                    result = cur.fetchone()
                    pending_users = result[0] if result else 0
            except Exception as e:
                print(f"Error getting pending users: {e}")
                pending_users = 0

            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                    result = cur.fetchone()
                    pending_feedback = result[0] if result else 0
            except Exception as e:
                print(f"Error getting pending feedback: {e}")
                pending_feedback = 0

            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                    result = cur.fetchone()
                    pending_diseases = result[0] if result else 0
            except Exception:
                pending_diseases = 0

            try:
                with get_db_cursor() as cur:
                    cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                    result = cur.fetchone()
                    pending_reviews = result[0] if result else 0
            except Exception as e:
                print(f"Error getting pending reviews: {e}")
                pending_reviews = 0

            sidebar_stats = {
                'pending_users': pending_users,
                'pending_feedback': pending_feedback,
                'pending_diseases': pending_diseases,
                'pending_reviews': pending_reviews
            }

            return render_template('admin/feedback.html',
                                   feedback=feedback_list,
                                   categories=categories,
                                   current_status=status,
                                   current_category=category,
                                   current_search=search,
                                   sidebar_stats=sidebar_stats)

        except Exception as e:
            print(f"Error loading feedback: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading feedback', 'error')
            return redirect(url_for('admin_dashboard'))

    @app.route("/admin/feedback/<int:feedback_id>", methods=["GET"])
    @login_required
    @admin_required
    def admin_get_feedback(feedback_id):
        """Admin - Get feedback details"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT f.*, u.username, u.full_name, u.email, u.user_type
                    FROM feedback f
                    LEFT JOIN users u ON f.user_id = u.id
                    WHERE f.id = %s
                """, (feedback_id,))

                row = cur.fetchone()
                if not row:
                    return jsonify({'error': 'Feedback not found'}), 404

                # Convert to dict (simplified)
                feedback = {
                    'id': row[0],
                    'user_id': row[1],
                    'diagnosis_id': row[2],
                    'name': row[3],
                    'email': row[4],
                    'feedback_type': row[5],
                    'subject': row[6],
                    'message': row[7],
                    'image_path': row[8],
                    'rating': row[9],
                    'accuracy_rating': row[10],
                    'feedback_text': row[11],
                    'suggestions': row[12],
                    'status': row[13],
                    'admin_response': row[14],
                    'created_at': row[15].isoformat() if row[15] else None,
                    'username': row[16],
                    'full_name': row[17],
                    'email': row[18] or row[4],
                    'user_type': row[19]
                }

            return jsonify(feedback)

        except Exception as e:
            print(f"Get feedback error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route("/admin/feedback/<int:feedback_id>/reply", methods=["POST"])
    @login_required
    @admin_required
    def admin_reply_feedback(feedback_id):
        """Admin - Reply to feedback"""
        try:
            data = request.get_json()
            reply = data.get('reply', '').strip()

            if not reply:
                return jsonify({'success': False, 'error': 'Reply cannot be empty'}), 400

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE feedback 
                    SET admin_response = %s
                    WHERE id = %s
                """, (reply, feedback_id))

            return jsonify({'success': True, 'message': 'Reply saved successfully'})

        except Exception as e:
            print(f"Reply feedback error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/admin/feedback/<int:feedback_id>/status", methods=["POST"])
    @login_required
    @admin_required
    def admin_update_feedback_status(feedback_id):
        """Admin - Manually update feedback status"""
        try:
            data = request.get_json()
            status = data.get('status')

            if status not in ['pending', 'reviewed', 'resolved']:
                return jsonify({'success': False, 'error': 'Invalid status'}), 400

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE feedback 
                    SET status = %s
                    WHERE id = %s
                """, (status, feedback_id))

            return jsonify({'success': True})

        except Exception as e:
            print(f"Update feedback status error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # ========== OTHER ADMIN ROUTES ==========
    @app.route("/admin/disease-library")
    @login_required
    @admin_required
    def admin_disease_library():
        """Admin - Disease library management"""
        try:
            crop = request.args.get('crop', 'corn')
            page = request.args.get('page', 1, type=int)
            per_page = 12
            offset = (page - 1) * per_page

            with get_db_cursor() as cur:
                # Get diseases with pagination
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
                         WHERE disease_code = di.disease_code AND crop = di.crop) as sample_count
                    FROM disease_info di
                    WHERE di.crop = %s
                    ORDER BY di.disease_code
                    LIMIT %s OFFSET %s
                """, (crop, per_page, offset))
                
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
                        'sample_count': row[10]
                    })

                # Get total count
                cur.execute("SELECT COUNT(*) as total FROM disease_info WHERE crop = %s", (crop,))
                total = cur.fetchone()[0] or 0

                # Get sample images for each disease
                for disease in diseases:
                    cur.execute("""
                        SELECT id 
                        FROM disease_samples 
                        WHERE crop = %s AND disease_code = %s 
                        ORDER BY display_order LIMIT 1
                    """, (crop, disease['disease_code']))
                    sample = cur.fetchone()
                    if sample:
                        disease['sample_image'] = url_for('get_disease_sample_image', sample_id=sample[0])
                    else:
                        disease['sample_image'] = None

                # Get crop statistics
                cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'corn'")
                corn_count = cur.fetchone()[0] or 0
                cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'rice'")
                rice_count = cur.fetchone()[0] or 0

                crop_stats = {'corn_count': corn_count, 'rice_count': rice_count}

                # Get sidebar stats
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = FALSE")
                pending_users = cur.fetchone()[0] or 0
                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()[0] or 0
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()[0] or 0

                try:
                    cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                    pending_diseases = cur.fetchone()[0] or 0
                except:
                    pending_diseases = 0

            sidebar_stats = {
                'pending_users': pending_users,
                'pending_feedback': pending_feedback,
                'pending_diseases': pending_diseases,
                'pending_reviews': pending_reviews
            }

            crop_display = 'Corn' if crop == 'corn' else 'Rice'

            # Simple pagination
            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page if total > 0 else 1
            }

            return render_template("admin/admin_disease_library.html",
                                   diseases=diseases,
                                   crop=crop,
                                   crop_display=crop_display,
                                   crop_stats=crop_stats,
                                   pagination=pagination,
                                   sidebar_stats=sidebar_stats,
                                   total_diseases=total)

        except Exception as e:
            print(f"Error in admin_disease_library: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Error loading disease library: {str(e)}', 'danger')
            return redirect(url_for('admin_dashboard'))

    @app.route("/admin/history")
    @login_required
    @admin_required
    def admin_history():
        """Admin view of all diagnosis history with expert reviews"""
        try:
            # Get filter parameters
            expert_review_status = request.args.get('expert_review_status', '')
            crop = request.args.get('crop', '')
            farmer = request.args.get('farmer', '')

            page = request.args.get('page', 1, type=int)
            per_page = 20
            offset = (page - 1) * per_page

            # Base query
            query = """
                SELECT 
                    dh.id, dh.user_id, dh.crop, dh.disease_detected,
                    dh.confidence, dh.symptoms, dh.recommendations,
                    dh.created_at, dh.expert_review_status,
                    dh.final_confidence_level, dh.image_processed,
                    u.username as farmer_name,
                    u2.username as reviewed_by_name
                FROM diagnosis_history dh
                JOIN users u ON dh.user_id = u.id
                LEFT JOIN users u2 ON dh.reviewed_by = u2.id
                WHERE 1=1
            """
            count_query = "SELECT COUNT(*) as total FROM diagnosis_history dh WHERE 1=1"
            params = []
            count_params = []

            # Apply filters
            if expert_review_status:
                query += " AND dh.expert_review_status = %s"
                count_query += " AND dh.expert_review_status = %s"
                params.append(expert_review_status)
                count_params.append(expert_review_status)

            if crop:
                query += " AND dh.crop = %s"
                count_query += " AND dh.crop = %s"
                params.append(crop)
                count_params.append(crop)

            if farmer:
                query += " AND u.username ILIKE %s"
                count_query += " AND u.username ILIKE %s"
                params.append(f'%{farmer}%')
                count_params.append(f'%{farmer}%')

            with get_db_cursor() as cur:
                # Get total count for pagination
                cur.execute(count_query, count_params)
                total = cur.fetchone()[0] or 0
                total_pages = (total + per_page - 1) // per_page if total > 0 else 1

                # Add pagination
                query += " ORDER BY dh.created_at DESC LIMIT %s OFFSET %s"
                params.extend([per_page, offset])

                cur.execute(query, params)
                diagnoses = []
                for row in cur.fetchall():
                    diagnoses.append({
                        'id': row[0],
                        'user_id': row[1],
                        'crop': row[2],
                        'disease_detected': row[3],
                        'confidence': row[4],
                        'symptoms': row[5],
                        'recommendations': row[6],
                        'created_at': row[7],
                        'expert_review_status': row[8],
                        'final_confidence_level': row[9],
                        'image_processed': row[10],
                        'farmer_name': row[11],
                        'reviewed_by_name': row[12]
                    })

                # Get statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN expert_review_status = 'accurate' THEN 1 ELSE 0 END) as accurate,
                        SUM(CASE WHEN expert_review_status = 'needs correction' THEN 1 ELSE 0 END) as needs_correction,
                        SUM(CASE WHEN expert_review_status = 'reject' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN expert_review_status IS NULL OR expert_review_status = 'pending' THEN 1 ELSE 0 END) as pending,
                        AVG(confidence) as avg_confidence
                    FROM diagnosis_history
                """)
                stats_row = cur.fetchone()
                stats = {
                    'total': stats_row[0] or 0,
                    'accurate': stats_row[1] or 0,
                    'needs_correction': stats_row[2] or 0,
                    'rejected': stats_row[3] or 0,
                    'pending': stats_row[4] or 0,
                    'avg_confidence': round(stats_row[5] or 0, 1)
                }

                # Get unique crops for filter
                cur.execute("SELECT DISTINCT crop FROM diagnosis_history WHERE crop IS NOT NULL ORDER BY crop")
                crops = [row[0] for row in cur.fetchall()]

                # Get sidebar stats
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = FALSE")
                pending_users = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()[0] or 0

            sidebar_stats = {
                'pending_users': pending_users,
                'pending_feedback': pending_feedback,
                'pending_diseases': 0,
                'pending_reviews': pending_reviews
            }

            filters = {
                'expert_review_status': expert_review_status,
                'crop': crop,
                'farmer': farmer
            }

            return render_template("admin/admin_history.html",
                                   diagnoses=diagnoses,
                                   stats=stats,
                                   crops=crops,
                                   page=page,
                                   total_pages=total_pages,
                                   total_diagnoses=total,
                                   filters=filters,
                                   sidebar_stats=sidebar_stats)

        except Exception as e:
            print(f"Error in admin_history: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading diagnosis history', 'danger')
            return redirect(url_for('admin_dashboard'))

    @app.route("/admin/analytics")
    @login_required
    @admin_required
    def admin_analytics():
        """Admin analytics page"""
        try:
            period = request.args.get('period', '30')
            days = int(period) if period and period.isdigit() else 30
            start_date = datetime.now() - timedelta(days=days)

            with get_db_cursor() as cur:
                # USER DISTRIBUTION
                cur.execute("""
                    SELECT 
                        user_type,
                        COUNT(*) as count
                    FROM users
                    GROUP BY user_type
                    ORDER BY count DESC
                """)
                user_distribution = []
                for row in cur.fetchall():
                    user_distribution.append({
                        'user_type': row[0],
                        'count': row[1]
                    })

                # DAILY NEW USERS
                cur.execute("""
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as new_users
                    FROM users
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, (start_date,))
                user_growth = []
                for row in cur.fetchall():
                    user_growth.append({
                        'date': row[0].strftime('%Y-%m-%d') if row[0] else None,
                        'new_users': row[1]
                    })

                # DAILY DIAGNOSES
                cur.execute("""
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as diagnoses
                    FROM diagnosis_history
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, (start_date,))
                daily_diagnoses = []
                for row in cur.fetchall():
                    daily_diagnoses.append({
                        'date': row[0].strftime('%Y-%m-%d') if row[0] else None,
                        'diagnoses': row[1]
                    })

                # DIAGNOSES BY CROP
                cur.execute("""
                    SELECT 
                        crop,
                        COUNT(*) as count,
                        AVG(confidence) as avg_confidence
                    FROM diagnosis_history
                    WHERE crop IS NOT NULL AND created_at >= %s
                    GROUP BY crop
                    ORDER BY count DESC
                    LIMIT 10
                """, (start_date,))
                top_crops = []
                for row in cur.fetchall():
                    top_crops.append({
                        'crop': row[0],
                        'count': row[1],
                        'avg_confidence': round(row[2] or 0, 1)
                    })

                # TOP DISEASES
                cur.execute("""
                    SELECT 
                        disease_detected,
                        COUNT(*) as count,
                        AVG(confidence) as avg_confidence
                    FROM diagnosis_history
                    WHERE disease_detected != 'Healthy Plant' 
                      AND disease_detected IS NOT NULL
                      AND created_at >= %s
                    GROUP BY disease_detected
                    ORDER BY count DESC
                    LIMIT 10
                """, (start_date,))
                top_diseases = []
                for row in cur.fetchall():
                    top_diseases.append({
                        'disease_detected': row[0],
                        'count': row[1],
                        'avg_confidence': round(row[2] or 0, 1)
                    })

                # Pending counts for sidebar
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = FALSE")
                pending_users = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()[0] or 0

            stats = {
                'pending_users': pending_users,
                'pending_feedback': pending_feedback
            }

            # Calculate summary stats
            total_users = sum(item['count'] for item in user_distribution)
            total_diagnoses = sum(item['diagnoses'] for item in daily_diagnoses) if daily_diagnoses else 0
            avg_daily_diagnoses = round(total_diagnoses / days, 1) if days > 0 else 0

            return render_template("admin/analytics.html",
                                   period=period,
                                   user_distribution=user_distribution,
                                   daily_diagnoses=daily_diagnoses,
                                   top_crops=top_crops,
                                   top_diseases=top_diseases,
                                   user_growth=user_growth,
                                   total_users=total_users,
                                   total_diagnoses=total_diagnoses,
                                   avg_daily_diagnoses=avg_daily_diagnoses,
                                   stats=stats,
                                   now=datetime.now())

        except Exception as e:
            print(f"Admin analytics error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading analytics', 'danger')
            return redirect(url_for('admin_dashboard'))

    @app.route("/admin/settings")
    @login_required
    @admin_required
    def admin_settings():
        """Admin settings page"""
        try:
            with get_db_cursor() as cur:
                # Get admin user data
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number, location, bio, profile_image,
                           is_active, created_at, last_login
                    FROM users 
                    WHERE id = %s
                """, (session['user_id'],))
                admin_row = cur.fetchone()
                
                admin = {
                    'id': admin_row[0],
                    'username': admin_row[1],
                    'email': admin_row[2],
                    'full_name': admin_row[3],
                    'user_type': admin_row[4],
                    'phone': admin_row[5],
                    'location': admin_row[6],
                    'bio': admin_row[7],
                    'profile_image': admin_row[8],
                    'is_active': admin_row[9],
                    'created_at': admin_row[10],
                    'last_login': admin_row[11]
                }

                # Get user settings
                try:
                    cur.execute("SELECT * FROM user_settings WHERE user_id = %s", (session['user_id'],))
                    settings_row = cur.fetchone()
                    if settings_row:
                        user_settings = {
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
                    else:
                        user_settings = {}
                except:
                    user_settings = {}

                # Get system statistics
                cur.execute("SELECT COUNT(*) as total FROM users")
                total_users = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as total FROM diagnosis_history")
                total_diagnoses = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as total FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()[0] or 0

            recent_activities = [
                {
                    'action': 'Logged in to admin panel',
                    'created_at': admin['last_login'] if admin['last_login'] else datetime.now()
                },
                {
                    'action': 'Viewed admin settings',
                    'created_at': datetime.now()
                }
            ]

            return render_template("admin/settings.html",
                                   admin=admin,
                                   user_settings=user_settings,
                                   total_users=total_users,
                                   total_diagnoses=total_diagnoses,
                                   pending_feedback=pending_feedback,
                                   recent_activities=recent_activities,
                                   now=datetime.now())

        except Exception as e:
            print(f"Admin settings error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading admin settings', 'danger')
            return redirect(url_for('admin_dashboard'))

    @app.route("/admin/settings/update", methods=["POST"])
    @login_required
    @admin_required
    def admin_update_settings():
        """Update admin profile settings"""
        try:
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            location = request.form.get('location')
            bio = request.form.get('bio')

            # Get notification preferences
            email_notifications = 1 if request.form.get('email_notifications') == 'on' else 0
            app_notifications = 1 if request.form.get('app_notifications') == 'on' else 0

            with get_db_cursor() as cur:
                # Update users table
                cur.execute("""
                    UPDATE users 
                    SET full_name = %s, email = %s, phone_number = %s, 
                        location = %s, bio = %s, updated_at = NOW()
                    WHERE id = %s
                """, (full_name, email, phone, location, bio, session['user_id']))

                # Update user_settings table
                try:
                    cur.execute("""
                        UPDATE user_settings 
                        SET email_notifications = %s, app_notifications = %s
                        WHERE user_id = %s
                    """, (email_notifications, app_notifications, session['user_id']))
                except:
                    # Try to insert if update fails
                    try:
                        cur.execute("""
                            INSERT INTO user_settings (user_id, email_notifications, app_notifications)
                            VALUES (%s, %s, %s)
                        """, (session['user_id'], email_notifications, app_notifications))
                    except:
                        pass

            # Update session
            session['full_name'] = full_name
            session['email'] = email

            flash('Admin profile updated successfully!', 'success')

        except Exception as e:
            print(f"Admin update settings error: {e}")
            flash('Error updating profile', 'danger')

        return redirect(url_for('admin_settings'))

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

    # ========== SETTINGS ROUTES ==========
    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        """User settings page with profile management"""
        user_id = session.get('user_id')

        if not user_id:
            return redirect(url_for('login'))

        # Get user information
        with get_db_cursor() as cur:
            cur.execute("""
                SELECT id, username, email, full_name, phone_number, 
                       location, profile_image, user_type, is_active, 
                       created_at, last_login, bio, language
                FROM users WHERE id = %s
            """, (user_id,))
            user_row = cur.fetchone()
            
            if not user_row:
                return redirect(url_for('login'))
            
            user = {
                'id': user_row[0],
                'username': user_row[1],
                'email': user_row[2],
                'full_name': user_row[3],
                'phone_number': user_row[4],
                'location': user_row[5],
                'profile_image': user_row[6],
                'user_type': user_row[7],
                'is_active': user_row[8],
                'created_at': user_row[9],
                'last_login': user_row[10],
                'bio': user_row[11],
                'language': user_row[12] if len(user_row) > 12 else 'en'
            }

            # Get user settings
            try:
                cur.execute("SELECT * FROM user_settings WHERE user_id = %s", (user_id,))
                settings_row = cur.fetchone()
                if settings_row:
                    user_settings = {
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
                else:
                    # Create default settings if they don't exist
                    cur.execute("""
                        INSERT INTO user_settings (user_id) VALUES (%s)
                    """, (user_id,))
                    user_settings = {
                        'email_notifications': True,
                        'email_updates': True,
                        'email_newsletter': False,
                        'email_promotions': False,
                        'app_notifications': True,
                        'app_security': True,
                        'app_reminders': True,
                        'frequency': 'realtime',
                        'profile_public': True,
                        'show_diagnosis': True,
                        'data_collection': True,
                        'theme': 'light',
                        'density': 'comfortable',
                        'auto_save': True,
                        'show_tips': True,
                        'detailed_results': True,
                        'quick_analysis': False,
                        'default_crop': '',
                        'measurement_unit': 'metric'
                    }
            except Exception as e:
                print(f"Error getting user settings: {e}")
                user_settings = {}

            # Get account statistics
            cur.execute("""
                SELECT 
                    created_at,
                    last_login,
                    (SELECT COUNT(*) FROM diagnosis_history WHERE user_id = %s) as total_diagnosis
                FROM users WHERE id = %s
            """, (user_id, user_id))
            stats_row = cur.fetchone()
            
            account_stats = {
                'created_at': stats_row[0],
                'last_login': stats_row[1],
                'total_diagnosis': stats_row[2] or 0
            }

        # Handle form submissions
        if request.method == 'POST':
            form_id = request.form.get('form_id')
            
            if form_id == 'accountForm':
                return handle_account_form(user_id, request.form)
            elif form_id == 'profileForm':
                return handle_profile_form(user_id, request)
            elif form_id == 'notificationsForm':
                return handle_notifications_form(user_id, request.form)
            elif form_id == 'privacyForm':
                return handle_privacy_form(user_id, request.form)
            elif form_id == 'preferencesForm':
                return handle_preferences_form(user_id, request.form)

        return render_template('settings.html',
                               user=user,
                               settings=user_settings,
                               account_stats=account_stats)

    # ========== SETTINGS FORM HANDLERS ==========
    def handle_account_form(user_id, form_data):
        """Handle account form submission"""
        email = form_data.get('email')
        current_password = form_data.get('current_password')
        new_password = form_data.get('new_password')
        confirm_password = form_data.get('confirm_password')

        with get_db_cursor() as cur:
            # Update email
            cur.execute("UPDATE users SET email = %s WHERE id = %s", (email, user_id))

            # Handle password change if provided
            if current_password and new_password and confirm_password:
                # Verify current password
                cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
                user_row = cur.fetchone()

                if user_row and check_password(current_password, user_row[0]):
                    if new_password == confirm_password:
                        new_hash = hash_password(new_password)
                        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
                        flash('Password updated successfully!', 'success')
                    else:
                        flash('New passwords do not match!', 'danger')
                        return redirect(url_for('settings') + '#account')
                else:
                    flash('Current password is incorrect!', 'danger')
                    return redirect(url_for('settings') + '#account')

        flash('Account settings updated successfully!', 'success')
        return redirect(url_for('settings') + '#account')

    def handle_profile_form(user_id, request):
        """Handle profile form with image upload"""
        # Get form data
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        location = request.form.get('location')
        language = request.form.get('language')
        bio = request.form.get('bio')

        # Get current user data to check existing image
        with get_db_cursor() as cur:
            cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
            user_row = cur.fetchone()
            old_image = user_row[0] if user_row else None

        # Handle profile image upload
        profile_image = None
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':
                ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
                
                def allowed_file(filename):
                    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

                if allowed_file(file.filename):
                    # Create upload directory if it doesn't exist
                    upload_folder = 'static/uploads/profiles'
                    os.makedirs(upload_folder, exist_ok=True)

                    # Generate secure filename
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    new_filename = f"{user_id}_{timestamp}_{filename}"

                    # Full path to save
                    filepath = os.path.join(upload_folder, new_filename)

                    # Save the file
                    file.save(filepath)

                    # Delete old profile image if exists
                    if old_image:
                        old_filepath = os.path.join('static/uploads/profiles', old_image)
                        if os.path.exists(old_filepath):
                            try:
                                os.remove(old_filepath)
                            except:
                                pass

                    profile_image = new_filename
                else:
                    flash('Invalid file type. Please upload JPG, PNG, or GIF.', 'danger')
                    return redirect(url_for('settings') + '#profile')

        # Update user profile
        with get_db_cursor() as cur:
            if profile_image:
                cur.execute("""
                    UPDATE users 
                    SET full_name = %s, phone_number = %s, location = %s, 
                        language = %s, bio = %s, profile_image = %s
                    WHERE id = %s
                """, (full_name, phone, location, language, bio, profile_image, user_id))
            else:
                cur.execute("""
                    UPDATE users 
                    SET full_name = %s, phone_number = %s, location = %s, 
                        language = %s, bio = %s
                    WHERE id = %s
                """, (full_name, phone, location, language, bio, user_id))

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('settings') + '#profile')

    def handle_notifications_form(user_id, form_data):
        """Handle notifications form submission"""
        # Get checkbox values (checkboxes return 'on' when checked)
        email_notifications = 1 if form_data.get('email_notifications') == 'on' else 0
        email_updates = 1 if form_data.get('email_updates') == 'on' else 0
        email_newsletter = 1 if form_data.get('email_newsletter') == 'on' else 0
        email_promotions = 1 if form_data.get('email_promotions') == 'on' else 0
        app_notifications = 1 if form_data.get('app_notifications') == 'on' else 0
        app_security = 1 if form_data.get('app_security') == 'on' else 0
        app_reminders = 1 if form_data.get('app_reminders') == 'on' else 0
        frequency = form_data.get('frequency', 'realtime')

        with get_db_cursor() as cur:
            cur.execute("""
                UPDATE user_settings 
                SET email_notifications = %s,
                    email_updates = %s,
                    email_newsletter = %s,
                    email_promotions = %s,
                    app_notifications = %s,
                    app_security = %s,
                    app_reminders = %s,
                    frequency = %s
                WHERE user_id = %s
            """, (email_notifications, email_updates, email_newsletter, email_promotions,
                  app_notifications, app_security, app_reminders, frequency, user_id))

        flash('Notification settings updated!', 'success')
        return redirect(url_for('settings') + '#notifications')

    def handle_privacy_form(user_id, form_data):
        """Handle privacy form submission"""
        profile_public = 1 if form_data.get('profile_public') == 'on' else 0
        show_diagnosis = 1 if form_data.get('show_diagnosis') == 'on' else 0
        data_collection = 1 if form_data.get('data_collection') == 'on' else 0

        with get_db_cursor() as cur:
            cur.execute("""
                UPDATE user_settings 
                SET profile_public = %s,
                    show_diagnosis = %s,
                    data_collection = %s
                WHERE user_id = %s
            """, (profile_public, show_diagnosis, data_collection, user_id))

        flash('Privacy settings updated!', 'success')
        return redirect(url_for('settings') + '#privacy')

    def handle_preferences_form(user_id, form_data):
        """Handle preferences form submission"""
        theme = form_data.get('theme', 'light')
        density = form_data.get('density', 'comfortable')
        auto_save = 1 if form_data.get('auto_save') == 'on' else 0
        show_tips = 1 if form_data.get('show_tips') == 'on' else 0
        detailed_results = 1 if form_data.get('detailed_results') == 'on' else 0
        quick_analysis = 1 if form_data.get('quick_analysis') == 'on' else 0
        default_crop = form_data.get('default_crop', '')
        measurement_unit = form_data.get('measurement_unit', 'metric')

        with get_db_cursor() as cur:
            cur.execute("""
                UPDATE user_settings 
                SET theme = %s,
                    density = %s,
                    auto_save = %s,
                    show_tips = %s,
                    detailed_results = %s,
                    quick_analysis = %s,
                    default_crop = %s,
                    measurement_unit = %s
                WHERE user_id = %s
            """, (theme, density, auto_save, show_tips, detailed_results,
                  quick_analysis, default_crop, measurement_unit, user_id))

        flash('Preferences updated!', 'success')
        return redirect(url_for('settings') + '#preferences')

    # ========== EXPERT DASHBOARD ROUTES ==========
    @app.route("/expert/dashboard")
    @login_required
    @expert_required
    def expert_dashboard():
        """Expert dashboard"""
        try:
            with get_db_cursor() as cur:
                # Get expert info
                cur.execute("""
                    SELECT username, full_name, email, profile_image, created_at
                    FROM users WHERE id = %s
                """, (session['user_id'],))
                expert_row = cur.fetchone()
                
                expert = {
                    'username': expert_row[0],
                    'full_name': expert_row[1],
                    'email': expert_row[2],
                    'profile_image': expert_row[3],
                    'created_at': expert_row[4]
                }

                # Get statistics
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history")
                total_diagnoses = cur.fetchone()[0] or 0

                cur.execute("SELECT COUNT(*) as count FROM disease_info")
                disease_count = cur.fetchone()[0] or 0

                # Get recent diagnoses needing review
                cur.execute("""
                    SELECT dh.id, dh.crop, dh.disease_detected, dh.confidence, 
                           dh.created_at, u.username as farmer_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.expert_review_status = 'pending' OR dh.expert_review_status IS NULL
                    ORDER BY dh.created_at DESC
                    LIMIT 10
                """)
                
                recent_diagnoses = []
                for row in cur.fetchall():
                    recent_diagnoses.append({
                        'id': row[0],
                        'crop': row[1],
                        'disease_detected': row[2],
                        'confidence': row[3],
                        'created_at': row[4],
                        'farmer_name': row[5]
                    })

            return render_template("expert/dashboard.html",
                                   expert=expert,
                                   pending_reviews=pending_reviews,
                                   total_diagnoses=total_diagnoses,
                                   disease_count=disease_count,
                                   recent_diagnoses=recent_diagnoses,
                                   now=datetime.now())

        except Exception as e:
            print(f"Expert dashboard error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading expert dashboard', 'danger')
            return redirect(url_for('dashboard'))

    @app.route("/expert/pending-reviews")
    @login_required
    @expert_required
    def expert_pending_reviews():
        """Expert - View pending diagnoses for review"""
        try:
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            with get_db_cursor() as cur:
                # Get total count
                cur.execute("""
                    SELECT COUNT(*) as total 
                    FROM diagnosis_history 
                    WHERE expert_review_status = 'pending' OR expert_review_status IS NULL
                """)
                total = cur.fetchone()[0] or 0
                total_pages = (total + per_page - 1) // per_page if total > 0 else 1

                # Get pending diagnoses
                cur.execute("""
                    SELECT dh.id, dh.user_id, dh.crop, dh.disease_detected, 
                           dh.confidence, dh.symptoms, dh.recommendations,
                           dh.created_at, dh.image_processed,
                           u.username as farmer_name, u.full_name as farmer_full_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.expert_review_status = 'pending' OR dh.expert_review_status IS NULL
                    ORDER BY dh.created_at DESC
                    LIMIT %s OFFSET %s
                """, (per_page, offset))

                diagnoses = []
                for row in cur.fetchall():
                    diagnoses.append({
                        'id': row[0],
                        'user_id': row[1],
                        'crop': row[2],
                        'disease_detected': row[3],
                        'confidence': row[4],
                        'symptoms': row[5],
                        'recommendations': row[6],
                        'created_at': row[7],
                        'image_processed': row[8],
                        'farmer_name': row[9],
                        'farmer_full_name': row[10]
                    })

                # Get all diseases for correction dropdown
                cur.execute("SELECT id, disease_name, crop FROM disease_info ORDER BY crop, disease_name")
                diseases = []
                for row in cur.fetchall():
                    diseases.append({
                        'id': row[0],
                        'disease_name': row[1],
                        'crop': row[2]
                    })

            return render_template("expert/pending_reviews.html",
                                   diagnoses=diagnoses,
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   diseases=diseases)

        except Exception as e:
            print(f"Pending reviews error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading pending reviews', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/history")
    @login_required
    @expert_required
    def expert_history():
        """Expert - View review history"""
        try:
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            with get_db_cursor() as cur:
                # Get total count
                cur.execute("""
                    SELECT COUNT(*) as total 
                    FROM diagnosis_history 
                    WHERE expert_review_status IS NOT NULL 
                    AND expert_review_status != 'pending'
                """)
                total = cur.fetchone()[0] or 0
                total_pages = (total + per_page - 1) // per_page if total > 0 else 1

                # Get review history
                cur.execute("""
                    SELECT dh.id, dh.user_id, dh.crop, dh.disease_detected, 
                           dh.confidence, dh.expert_review_status,
                           dh.created_at, dh.reviewed_at,
                           u.username as farmer_name,
                           ru.username as reviewed_by_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    LEFT JOIN users ru ON dh.reviewed_by = ru.id
                    WHERE dh.expert_review_status IS NOT NULL 
                    AND dh.expert_review_status != 'pending'
                    ORDER BY dh.reviewed_at DESC NULLS LAST, dh.created_at DESC
                    LIMIT %s OFFSET %s
                """, (per_page, offset))

                reviews = []
                for row in cur.fetchall():
                    reviews.append({
                        'id': row[0],
                        'user_id': row[1],
                        'crop': row[2],
                        'disease_detected': row[3],
                        'confidence': row[4],
                        'expert_review_status': row[5],
                        'created_at': row[6],
                        'reviewed_at': row[7],
                        'farmer_name': row[8],
                        'reviewed_by_name': row[9]
                    })

                # Get statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_reviews,
                        SUM(CASE WHEN expert_review_status = 'accurate' THEN 1 ELSE 0 END) as approved_count,
                        SUM(CASE WHEN expert_review_status = 'needs correction' THEN 1 ELSE 0 END) as correction_count,
                        SUM(CASE WHEN expert_review_status = 'reject' THEN 1 ELSE 0 END) as rejected_count
                    FROM diagnosis_history 
                    WHERE expert_review_status IS NOT NULL 
                    AND expert_review_status != 'pending'
                """)
                stats_row = cur.fetchone()
                stats = {
                    'total_reviews': stats_row[0] or 0,
                    'approved_count': stats_row[1] or 0,
                    'correction_count': stats_row[2] or 0,
                    'rejected_count': stats_row[3] or 0
                }

            return render_template("expert/history.html",
                                   reviews=reviews,
                                   page=page,
                                   total_pages=total_pages,
                                   total_results=total,
                                   stats=stats)

        except Exception as e:
            print(f"Expert history error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading review history', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/questions")
    @login_required
    @expert_required
    def expert_questions():
        """Expert - Manage questions"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT q.id, q.crop, q.disease_code, q.question_text, 
                           q.question_category, q.display_order, q.created_at,
                           di.disease_name
                    FROM questions q
                    LEFT JOIN disease_info di ON q.crop = di.crop AND q.disease_code = di.disease_code
                    ORDER BY q.crop, q.disease_code, q.display_order
                """)

                questions = []
                for row in cur.fetchall():
                    questions.append({
                        'id': row[0],
                        'crop': row[1],
                        'disease_code': row[2],
                        'question_text': row[3],
                        'question_category': row[4],
                        'display_order': row[5],
                        'created_at': row[6],
                        'disease_name': row[7] or row[2]
                    })

                # Get unique values for filters
                cur.execute("SELECT DISTINCT crop FROM questions ORDER BY crop")
                crops = [row[0] for row in cur.fetchall()]

                cur.execute("SELECT DISTINCT disease_code FROM questions ORDER BY disease_code")
                diseases = [row[0] for row in cur.fetchall()]

                cur.execute("SELECT DISTINCT question_category FROM questions ORDER BY question_category")
                categories = [row[0] for row in cur.fetchall()]

            return render_template("expert/questions.html",
                                   questions=questions,
                                   crops=crops,
                                   diseases=diseases,
                                   categories=categories)

        except Exception as e:
            print(f"Expert questions error: {e}")
            flash('Error loading questions', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/diseases")
    @login_required
    @expert_required
    def expert_diseases():
        """Expert - Disease library management"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT id, crop, disease_code, disease_name, cause, 
                           symptoms, organic_treatment, chemical_treatment, 
                           prevention, manual_treatment, created_at
                    FROM disease_info 
                    ORDER BY crop, disease_name
                """)

                diseases = []
                for row in cur.fetchall():
                    diseases.append({
                        'id': row[0],
                        'crop': row[1],
                        'disease_code': row[2],
                        'disease_name': row[3],
                        'cause': row[4],
                        'symptoms': row[5],
                        'organic_treatment': row[6],
                        'chemical_treatment': row[7],
                        'prevention': row[8],
                        'manual_treatment': row[9],
                        'created_at': row[10]
                    })

                # Get unique crops for filter
                cur.execute("SELECT DISTINCT crop FROM disease_info ORDER BY crop")
                crops = [row[0] for row in cur.fetchall()]

            return render_template("expert/diseases.html",
                                   diseases=diseases,
                                   crops=crops)

        except Exception as e:
            print(f"Expert diseases error: {e}")
            flash('Error loading diseases', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/settings")
    @login_required
    @expert_required
    def expert_settings():
        """Expert settings page"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, full_name, phone_number, 
                           location, bio, profile_image, created_at, last_login
                    FROM users 
                    WHERE id = %s
                """, (session['user_id'],))
                user_row = cur.fetchone()

                user = {
                    'id': user_row[0],
                    'username': user_row[1],
                    'email': user_row[2],
                    'full_name': user_row[3],
                    'phone': user_row[4],
                    'location': user_row[5],
                    'bio': user_row[6],
                    'profile_image': user_row[7],
                    'created_at': user_row[8],
                    'last_login': user_row[9]
                }

            return render_template("expert/settings.html", user=user)

        except Exception as e:
            print(f"Expert settings error: {e}")
            flash('Error loading settings', 'danger')
            return redirect(url_for('expert_dashboard'))

    # Return the app
    return app