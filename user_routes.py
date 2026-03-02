Here's the PostgreSQL version of your `user_routes.py`. I've converted all MySQL-specific syntax to PostgreSQL:

```python
# user_routes.py (PostgreSQL version)
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError

from flask import render_template, request, session, redirect, url_for, flash, jsonify, Response, make_response, \
    send_file

from db_config import get_db, get_db_cursor, get_db_cursor_readonly
from auth import hash_password, check_password, validate_email, validate_password, login_required
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from datetime import time as datetime_time
import csv
from io import StringIO
from datetime import datetime

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
    """Require admin privileges for route - NO inner decorators!"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Don't put @login_required here - let it be applied separately
        if session.get('user_type') != 'admin':
            if request.is_json:
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def expert_required(f):
    """Require expert privileges for route - NO inner decorators!"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Don't put @login_required here - let it be applied separately
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
            with get_db_cursor_readonly() as cur:
                # FIXED: Use expert_review_status = 'pending'
                cur.execute("""
                    SELECT COUNT(*) as count 
                    FROM diagnosis_history 
                    WHERE expert_review_status = 'pending' OR expert_review_status IS NULL
                """)
                result = cur.fetchone()
                return result['count'] or 0
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

                # Check if user exists
                with get_db_cursor_readonly() as cur:
                    cur.execute("SELECT id FROM users WHERE username = %s OR email = %s",
                                (username, email))
                    if cur.fetchone():
                        flash('Username or email already exists!', 'danger')
                        return render_template("register.html", redirect_to=redirect_after)

                # Create user
                password_hash = hash_password(password)
                with get_db_cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (username, email, password_hash, full_name, 
                                          user_type, phone_number, location)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (username, email, password_hash, full_name, user_type, phone, location))

                    user_id = cur.fetchone()['id']

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
                            pass

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

        except IntegrityError as e:
            print(f"Registration integrity error: {e}")
            flash('Registration failed. Username or email may already exist.', 'danger')
            return render_template("register.html", redirect_to=redirect_to)
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

                with get_db_cursor_readonly() as cur:
                    # Get user
                    cur.execute("""
                        SELECT id, username, email, password_hash, user_type, 
                               full_name, is_active, profile_image
                        FROM users 
                        WHERE username = %s OR email = %s
                    """, (username, username))

                    user = cur.fetchone()

                if user:
                    print(f"✅ User found: {user['username']}, Type: {user['user_type']}, Active: {user['is_active']}")
                else:
                    print(f"❌ User not found: {username}")

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
                    with get_db_cursor() as cur:
                        cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))

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
            with get_db_cursor_readonly() as cur:
                # Get user stats
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_diagnoses,
                        COUNT(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 END) as today_diagnoses,
                        AVG(confidence) as avg_confidence
                    FROM diagnosis_history 
                    WHERE user_id = %s
                """, (user_id,))
                stats = cur.fetchone()

                if not stats:
                    stats = {'total_diagnoses': 0, 'today_diagnoses': 0, 'avg_confidence': 0}
                else:
                    stats['avg_confidence'] = round(stats['avg_confidence'] or 0, 1)

                # Get saved count
                try:
                    cur.execute("""
                        SELECT COUNT(*) as saved_count
                        FROM saved_diagnoses 
                        WHERE user_id = %s
                    """, (user_id,))
                    saved_result = cur.fetchone()
                    saved_count = saved_result['saved_count'] if saved_result else 0
                except:
                    saved_count = 0
                    print("Note: saved_diagnoses table might not exist")

                # Get recent diagnoses
                cur.execute("""
                    SELECT id, crop, disease_detected, confidence, 
                           created_at as diagnosis_date
                    FROM diagnosis_history 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 5
                """, (user_id,))
                recent_diagnoses = cur.fetchall()

                # Get top diseases
                cur.execute("""
                    SELECT disease_detected, COUNT(*) as count
                    FROM diagnosis_history 
                    WHERE user_id = %s 
                    GROUP BY disease_detected 
                    ORDER BY count DESC 
                    LIMIT 5
                """, (user_id,))
                top_diseases = cur.fetchall()

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
            with get_db_cursor_readonly() as cur:
                # Get user data
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

                # Get stats
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_diagnosis,
                        (SELECT COUNT(*) FROM saved_diagnoses WHERE user_id = %s) as saved_items,
                        EXTRACT(DAY FROM NOW() - MIN(created_at)) as days_active
                    FROM diagnosis_history 
                    WHERE user_id = %s
                """, (user_id, user_id))
                stats = cur.fetchone()

                # Get recent activity
                cur.execute("""
                    (SELECT 
                        'diagnosis' as type,
                        CONCAT('Diagnosed ', disease_detected) as title,
                        CONCAT('Crop: ', crop) as description,
                        created_at as time,
                        CONCAT('/diagnosis/', id) as link
                    FROM diagnosis_history 
                    WHERE user_id = %s)
                    UNION ALL
                    (SELECT 
                        'save' as type,
                        CONCAT('Saved ', disease_detected) as title,
                        'Saved diagnosis for later' as description,
                        sd.created_at as time,
                        CONCAT('/diagnosis/', dh.id) as link
                    FROM saved_diagnoses sd
                    JOIN diagnosis_history dh ON sd.id = dh.id
                    WHERE sd.user_id = %s)
                    ORDER BY time DESC
                    LIMIT 10
                """, (user_id, user_id))
                recent_activity = cur.fetchall()

                # Format time for display
                for activity in recent_activity:
                    if activity['time']:
                        activity['time'] = activity['time'].strftime('%Y-%m-%d %H:%M')

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
                crop_expertise = cur.fetchall()

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
                common_diseases = cur.fetchall()

                # Format last_detected
                for disease in common_diseases:
                    if disease['last_detected']:
                        disease['last_detected'] = disease['last_detected'].strftime('%Y-%m-%d')

                # Calculate profile completion
                completion_items = [
                    {'label': 'Profile Picture', 'completed': bool(user.get('profile_image')), 'action': '#'},
                    {'label': 'Bio', 'completed': bool(user.get('bio')), 'action': '#'},
                    {'label': 'Phone Number', 'completed': bool(user.get('phone_number')), 'action': '/settings'},
                    {'label': 'Location', 'completed': bool(user.get('location')), 'action': '/settings'},
                    {'label': 'First Diagnosis', 'completed': stats and stats['total_diagnosis'] > 0, 'action': '/upload'},
                    {'label': 'Saved Item', 'completed': stats and stats['saved_items'] > 0, 'action': '/history'},
                ]

                completed_count = sum(1 for item in completion_items if item['completed'])
                profile_completion = int((completed_count / len(completion_items)) * 100) if completion_items else 0

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
            with get_db_cursor_readonly() as cur:
                cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

            # Delete old image if exists
            if user and user.get('profile_image'):
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', user['profile_image'])
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

            with get_db_cursor_readonly() as cur:
                # Get current password hash
                cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

            if not user or not check_password(current_password, user['password_hash']):
                return jsonify({'success': False, 'message': 'Current password is incorrect!'})

            # Update password
            new_hash = hash_password(new_password)
            with get_db_cursor() as cur:
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

            with get_db_cursor_readonly() as cur:
                # --- BUILD MAIN QUERY WITH FILTERS ---
                query = """
                    SELECT dh.id, dh.crop, dh.disease_detected, dh.confidence, 
                           dh.symptoms, dh.recommendations, dh.created_at,
                           dh.image_path,
                           (SELECT COUNT(*) FROM saved_diagnoses WHERE id = dh.id AND user_id = %s) > 0 as saved
                    FROM diagnosis_history dh
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
                            WHERE id = dh.id AND user_id = %s
                        )
                    """
                    params.append(user_id)

                # ADD ORDER BY AND PAGINATION
                query += " ORDER BY dh.created_at DESC LIMIT %s OFFSET %s"
                params.extend([per_page, offset])

                # EXECUTE QUERY
                cur.execute(query, params)
                diagnoses = cur.fetchall()

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
                            WHERE id = dh.id AND user_id = %s
                        )
                    """
                    count_params.append(user_id)

                cur.execute(count_query, count_params)
                total = cur.fetchone()['total']

                # Monthly diagnoses (using same filters)
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
                monthly_diagnoses = cur.fetchone()['monthly_diagnoses'] or 0

                # Average confidence
                avg_conf_query = """
                    SELECT COALESCE(AVG(confidence), 0) as avg_confidence
                    FROM diagnosis_history dh
                    WHERE dh.user_id = %s
                """
                avg_conf_params = [user_id]

                if date_from:
                    avg_conf_query += " AND DATE(dh.created_at) >= %s"
                    avg_conf_params.append(date_from)
                if date_to:
                    avg_conf_query += " AND DATE(dh.created_at) <= %s"
                    avg_conf_params.append(date_to)
                if crops and crops[0] != '':
                    placeholders = ', '.join(['%s'] * len(crops))
                    avg_conf_query += f" AND dh.crop IN ({placeholders})"
                    avg_conf_params.extend(crops)
                if diseases and diseases[0] != '':
                    placeholders = ', '.join(['%s'] * len(diseases))
                    avg_conf_query += f" AND dh.disease_detected IN ({placeholders})"
                    avg_conf_params.extend(diseases)

                cur.execute(avg_conf_query, avg_conf_params)
                avg_confidence = round(cur.fetchone()['avg_confidence'] or 0, 1)

                # Saved count
                cur.execute("""
                    SELECT COUNT(*) as saved_count
                    FROM saved_diagnoses
                    WHERE user_id = %s
                """, (user_id,))
                saved_count = cur.fetchone()['saved_count'] or 0

                # Get available crops for filter dropdown
                cur.execute("""
                    SELECT DISTINCT crop 
                    FROM diagnosis_history 
                    WHERE user_id = %s AND crop IS NOT NULL
                    ORDER BY crop
                """, (user_id,))
                available_crops = [row['crop'] for row in cur.fetchall()]

                # Get available diseases for filter dropdown
                cur.execute("""
                    SELECT DISTINCT disease_detected 
                    FROM diagnosis_history 
                    WHERE user_id = %s AND disease_detected IS NOT NULL
                    ORDER BY disease_detected
                """, (user_id,))
                available_diseases = [row['disease_detected'] for row in cur.fetchall()]

            # --- PAGINATION OBJECT ---
            total_pages = (total + per_page - 1) // per_page if total > 0 else 1

            def iter_pages():
                """Generate page numbers for pagination"""
                start = max(1, page - 2)
                end = min(total_pages, page + 2) + 1
                return range(start, end)

            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': total_pages,
                'has_prev': page > 1,
                'has_next': page < total_pages,
                'prev_num': page - 1 if page > 1 else None,
                'next_num': page + 1 if page < total_pages else None,
                'iter_pages': iter_pages
            }

            # Build query string for pagination links
            query_params = []
            if date_from:
                query_params.append(f"date_from={date_from}")
            if date_to:
                query_params.append(f"date_to={date_to}")
            if crops and crops[0] != '':
                query_params.append(f"crops={','.join(crops)}")
            if diseases and diseases[0] != '':
                query_params.append(f"diseases={','.join(diseases)}")
            if saved_only:
                query_params.append("saved_only=true")

            query_string = '&'.join(query_params)
            if query_string:
                query_string = '?' + query_string

            total_diagnoses = total

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

            with get_db_cursor_readonly() as cur:
                # Get diagnosis details
                cur.execute("""
                    SELECT * FROM diagnosis_history 
                    WHERE id = %s AND user_id = %s
                """, (diagnosis_id, user_id))

                diagnosis = cur.fetchone()

            if not diagnosis:
                flash('Diagnosis not found', 'danger')
                return redirect(url_for('my_diagnoses'))

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
                        INSERT INTO saved_diagnoses (user_id, id, notes)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (user_id, id) DO NOTHING
                    """, (user_id, diagnosis_id, notes))
                    message = 'Diagnosis saved!'
                else:
                    cur.execute("""
                        DELETE FROM saved_diagnoses 
                        WHERE user_id = %s AND id = %s
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
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT sd.*, dh.image_path, dh.crop as history_crop, 
                           dh.disease_detected, dh.confidence as history_confidence,
                           dh.symptoms as history_symptoms, dh.recommendations as history_recommendations
                    FROM saved_diagnoses sd
                    LEFT JOIN diagnosis_history dh ON sd.id = dh.id
                    WHERE sd.user_id = %s
                    ORDER BY sd.created_at DESC
                """, (user_id,))
                saved_diagnoses = cur.fetchall()

            # --- CALCULATE STATS ---
            total_saved = len(saved_diagnoses)

            # Get disease names
            diseases_list = []
            for d in saved_diagnoses:
                disease = d.get('disease_detected') or d.get('disease')
                if disease:
                    diseases_list.append(disease)
            unique_diseases = len(set(diseases_list))

            # Get crop names
            crops_list = []
            for d in saved_diagnoses:
                crop = d.get('history_crop') or d.get('crop')
                if crop:
                    crops_list.append(crop)
            unique_crops = len(set(crops_list))

            # Average confidence
            confidence_values = []
            for d in saved_diagnoses:
                conf = d.get('history_confidence') or d.get('confidence')
                if conf:
                    confidence_values.append(float(conf))

            if confidence_values:
                avg_confidence = round(sum(confidence_values) / len(confidence_values), 1)
            else:
                avg_confidence = 0

            # Get unique crops for filter dropdown
            crops = sorted(list(set([(d.get('history_crop') or d.get('crop')) for d in saved_diagnoses if
                                     (d.get('history_crop') or d.get('crop'))])))

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
            with get_db_cursor_readonly() as cur:
                # First, get the image path to delete the file
                cur.execute("""
                    SELECT image_path FROM diagnosis_history 
                    WHERE id = %s AND user_id = %s
                """, (diagnosis_id, user_id))
                result = cur.fetchone()

            if result and result['image_path']:
                image_path = result['image_path']
                # Try to delete the image file
                try:
                    app_dir = os.path.dirname(os.path.abspath(__file__))
                    if os.path.isabs(image_path):
                        full_path = image_path
                    elif image_path.startswith('static/'):
                        full_path = os.path.join(app_dir, image_path)
                    elif image_path.startswith('uploads/'):
                        full_path = os.path.join(app_dir, 'static', image_path)
                    else:
                        full_path = os.path.join(app_dir, 'static', 'uploads', image_path)

                    if os.path.exists(full_path):
                        os.remove(full_path)
                        print(f"🗑️ Deleted image file: {full_path}")
                except Exception as e:
                    print(f"⚠️ Could not delete image file: {e}")

            with get_db_cursor() as cur:
                # Delete from saved_diagnoses first
                cur.execute("""
                    DELETE FROM saved_diagnoses 
                    WHERE id = %s
                """, (diagnosis_id,))

                # Then delete the diagnosis
                cur.execute("""
                    DELETE FROM diagnosis_history 
                    WHERE id = %s AND user_id = %s
                """, (diagnosis_id, user_id))

            return jsonify({'success': True, 'message': 'Diagnosis deleted successfully'})

        except Exception as e:
            print(f"Delete error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/admin/fix-paths')
    @admin_required
    def fix_image_paths():
        """Clean up image paths in database"""
        try:
            with get_db_cursor() as cur:
                # Fix records with 'uploads/' prefix
                cur.execute("""
                    UPDATE diagnosis_history 
                    SET image_path = REPLACE(image_path, 'uploads/', '')
                    WHERE image_path LIKE 'uploads/%'
                """)
                updated = cur.rowcount

            return f"✅ Fixed {updated} records. Images should now load correctly."

        except Exception as e:
            return f"Error: {str(e)}"

    @app.route("/api/diagnosis/delete-all", methods=["DELETE"])
    @login_required
    def delete_all_diagnoses():
        """Delete all diagnoses for current user"""
        user_id = session['user_id']

        try:
            with get_db_cursor_readonly() as cur:
                # Get all image paths to delete files
                cur.execute("""
                    SELECT image_path FROM diagnosis_history
                    WHERE user_id = %s AND image_path IS NOT NULL
                """, (user_id,))
                images = cur.fetchall()

            # Delete image files
            app_dir = os.path.dirname(os.path.abspath(__file__))
            for img in images:
                if img['image_path']:
                    try:
                        image_path = img['image_path']
                        if os.path.isabs(image_path):
                            full_path = image_path
                        elif image_path.startswith('static/'):
                            full_path = os.path.join(app_dir, image_path)
                        elif image_path.startswith('uploads/'):
                            full_path = os.path.join(app_dir, 'static', image_path)
                        else:
                            full_path = os.path.join(app_dir, 'static', 'uploads', image_path)

                        if os.path.exists(full_path):
                            os.remove(full_path)
                    except Exception as e:
                        print(f"⚠️ Could not delete image file: {e}")

            with get_db_cursor() as cur:
                # Delete from saved_diagnoses first
                cur.execute("""
                    DELETE FROM saved_diagnoses 
                    WHERE user_id = %s
                """, (user_id,))

                # Then delete all diagnoses
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

    @app.route('/api/diagnosis/<int:id>/toggle-save', methods=['POST'])
    @login_required
    def toggle_save_diagnosis(id):
        """Toggle save status of a diagnosis"""
        try:
            user_id = session['user_id']

            with get_db_cursor_readonly() as cur:
                # Check if already saved
                cur.execute("""
                    SELECT id FROM saved_diagnoses 
                    WHERE user_id = %s AND id = %s
                """, (user_id, id))
                existing = cur.fetchone()

            with get_db_cursor() as cur:
                if existing:
                    # Remove from saved
                    cur.execute("""
                        DELETE FROM saved_diagnoses 
                        WHERE user_id = %s AND id = %s
                    """, (user_id, id))
                    saved = False
                    message = "Diagnosis removed from saved"
                else:
                    # Get diagnosis details from history
                    with get_db_cursor_readonly() as cur2:
                        cur2.execute("""
                            SELECT id, crop, disease_detected, confidence, 
                                   symptoms, recommendations, final_confidence_level, created_at
                            FROM diagnosis_history WHERE id = %s
                        """, (id,))
                        diagnosis = cur2.fetchone()

                    if not diagnosis:
                        return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

                    # Save to saved_diagnoses
                    cur.execute("""
                        INSERT INTO saved_diagnoses 
                        (id, user_id, crop, disease, confidence, 
                         symptoms, recommendations, status, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        id,
                        user_id,
                        diagnosis['crop'],
                        diagnosis['disease_detected'],
                        diagnosis['confidence'],
                        diagnosis['symptoms'],
                        diagnosis['recommendations'],
                        diagnosis.get('final_confidence_level', 'AI Only'),
                        diagnosis['created_at']
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

            with get_db_cursor_readonly() as cur:
                placeholders = ','.join(['%s'] * len(ids))
                cur.execute(f"""
                    SELECT id FROM saved_diagnoses 
                    WHERE user_id = %s AND id IN ({placeholders})
                """, [user_id] + ids)

                saved = [row['id'] for row in cur.fetchall()]

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
                with get_db_cursor_readonly() as cur:
                    # Check if table exists first (PostgreSQL way)
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_name = 'feedback'
                        )
                    """)
                    table_exists = cur.fetchone()['exists']

                    if table_exists:
                        cur.execute("""
                            SELECT * FROM feedback 
                            WHERE user_id = %s 
                            ORDER BY created_at DESC 
                            LIMIT 10
                        """, (user_id,))
                        user_feedback = cur.fetchall()

        except Exception as e:
            print(f"Error loading user feedback: {e}")

        return render_template('feedback.html', user_feedback=user_feedback)

    @app.route('/feedback')
    def feedback_page():
        """Display feedback form and user's previous feedback"""
        user_feedback = []

        # If user is logged in, get their previous feedback
        if session.get('user_id'):
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT * FROM feedback 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """, (session['user_id'],))

                user_feedback = cur.fetchall()

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
            contact_preference = request.form.get('contact_preference', 'email')

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
                user_id = None  # Don't link to user account
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
        """Test feedback table structure"""
        try:
            with get_db_cursor_readonly() as cur:
                # Check if table exists
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'feedback'
                    )
                """)
                table_exists = cur.fetchone()['exists']

                if not table_exists:
                    return "❌ feedback table does not exist!"

                # Show table structure
                cur.execute("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = 'feedback'
                    ORDER BY ordinal_position
                """)
                columns = cur.fetchall()

                result = "<h3>Feedback Table Structure:</h3><ul>"
                for col in columns:
                    result += f"<li>{col['column_name']} - {col['data_type']}</li>"
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
            with get_db_cursor_readonly() as cur:
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

                with get_db_cursor() as cur:
                    cur.execute("""
                        INSERT INTO feedback 
                        (user_id, diagnosis_id, rating, accuracy_rating, 
                         feedback_text, suggestions)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (user_id, diagnosis_id) DO UPDATE SET
                        rating = EXCLUDED.rating,
                        accuracy_rating = EXCLUDED.accuracy_rating,
                        feedback_text = EXCLUDED.feedback_text,
                        suggestions = EXCLUDED.suggestions,
                        created_at = NOW()
                    """, (user_id, diagnosis_id, rating, accuracy, feedback_text, suggestions))

                flash('Thank you for your feedback!', 'success')
                return redirect(url_for('view_diagnosis', diagnosis_id=diagnosis_id))

            # GET request - show feedback form
            with get_db_cursor_readonly() as cur:
                cur.execute("SELECT * FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
                diagnosis = cur.fetchone()

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
            with get_db_cursor_readonly() as cur:
                # Overall stats
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_feedback,
                        AVG(rating) as avg_rating,
                        AVG(accuracy_rating) as avg_accuracy,
                        COUNT(DISTINCT user_id) as unique_users
                    FROM feedback
                """)
                stats = cur.fetchone()

                # Recent feedback
                cur.execute("""
                    SELECT f.*, u.username, u.full_name, dh.disease_detected
                    FROM feedback f
                    LEFT JOIN users u ON f.user_id = u.id
                    LEFT JOIN diagnosis_history dh ON f.diagnosis_id = dh.id
                    ORDER BY f.created_at DESC
                    LIMIT 10
                """)
                recent_feedback = cur.fetchall()

            return jsonify({
                'stats': stats,
                'recent_feedback': recent_feedback
            })

        except Exception as e:
            print(f"Feedback stats error: {e}")
            return jsonify({'error': str(e)}), 500

    # ========== ADMIN DASHBOARD ==========

    @app.route("/admin/dashboard")
    @admin_required
    def admin_dashboard():
        """Admin dashboard with comprehensive analytics"""
        try:
            with get_db_cursor_readonly() as cur:
                # Get user statistics
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_users,
                        SUM(CASE WHEN is_active = true THEN 1 ELSE 0 END) as active_users,
                        SUM(CASE WHEN is_active = false OR is_active IS NULL THEN 1 ELSE 0 END) as inactive_users,
                        SUM(CASE WHEN user_type = 'farmer' THEN 1 ELSE 0 END) as total_farmers,
                        SUM(CASE WHEN user_type = 'expert' THEN 1 ELSE 0 END) as total_experts,
                        SUM(CASE WHEN user_type = 'researcher' THEN 1 ELSE 0 END) as total_researchers,
                        SUM(CASE WHEN user_type = 'student' THEN 1 ELSE 0 END) as total_students,
                        SUM(CASE WHEN user_type = 'admin' THEN 1 ELSE 0 END) as total_admins
                    FROM users
                """)
                user_stats = cur.fetchone()

                # Active users today
                cur.execute("""
                    SELECT COUNT(DISTINCT user_id) as active_today
                    FROM diagnosis_history
                    WHERE DATE(created_at) = CURRENT_DATE
                """)
                active_today = cur.fetchone()['active_today'] or 0
                active_today = int(active_today)

                # ===== DIAGNOSIS STATISTICS =====
                cur.execute("SELECT COUNT(*) as total FROM diagnosis_history")
                total_diagnoses = cur.fetchone()['total'] or 0
                total_diagnoses = int(total_diagnoses)

                cur.execute("""
                    SELECT COUNT(*) as monthly
                    FROM diagnosis_history
                    WHERE EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) 
                    AND EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM CURRENT_DATE)
                """)
                monthly_diagnoses = cur.fetchone()['monthly'] or 0
                monthly_diagnoses = int(monthly_diagnoses)

                # Average confidence
                cur.execute("""
                    SELECT ROUND(AVG(confidence), 1) as avg_confidence
                    FROM diagnosis_history
                """)
                avg_confidence = cur.fetchone()['avg_confidence'] or 0
                avg_confidence = int(avg_confidence)

                # Top diseases detected
                cur.execute("""
                    SELECT 
                        disease_detected,
                        COUNT(*) as count,
                        ROUND(AVG(confidence), 1) as avg_confidence
                    FROM diagnosis_history
                    WHERE disease_detected != 'healthy' AND disease_detected IS NOT NULL
                    GROUP BY disease_detected
                    ORDER BY count DESC
                    LIMIT 5
                """)
                top_diseases = cur.fetchall()

                # Convert values in top_diseases
                for disease in top_diseases:
                    disease['count'] = int(disease['count'])
                    disease['avg_confidence'] = float(disease['avg_confidence']) if disease['avg_confidence'] else 0

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
                diagnoses_by_crop = cur.fetchall()

                for crop in diagnoses_by_crop:
                    crop['count'] = int(crop['count'])

                # ===== DISEASE INFO STATISTICS =====
                cur.execute("SELECT COUNT(*) as total_diseases FROM disease_info")
                total_diseases = cur.fetchone()['total_diseases'] or 0
                total_diseases = int(total_diseases)

                # Disease distribution by crop from disease_info
                cur.execute("""
                    SELECT 
                        crop,
                        COUNT(*) as disease_count
                    FROM disease_info
                    GROUP BY crop
                    ORDER BY disease_count DESC
                """)
                disease_by_crop = cur.fetchall()

                for crop in disease_by_crop:
                    crop['disease_count'] = int(crop['disease_count'])

                # ===== FEEDBACK STATISTICS =====
                # Check if feedback table exists
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'feedback'
                    ) as table_exists
                """)
                feedback_table_exists = cur.fetchone()['table_exists']

                if feedback_table_exists:
                    cur.execute("""
                        SELECT 
                            COUNT(*) as total_feedback,
                            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_feedback,
                            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_feedback
                        FROM feedback
                    """)
                    feedback_stats = cur.fetchone()
                    if feedback_stats:
                        feedback_stats['total_feedback'] = int(feedback_stats['total_feedback'] or 0)
                        feedback_stats['pending_feedback'] = int(feedback_stats['pending_feedback'] or 0)
                        feedback_stats['resolved_feedback'] = int(feedback_stats['resolved_feedback'] or 0)
                    else:
                        feedback_stats = {'total_feedback': 0, 'pending_feedback': 0, 'resolved_feedback': 0}
                else:
                    feedback_stats = {'total_feedback': 0, 'pending_feedback': 0, 'resolved_feedback': 0}

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
                recent_activities = cur.fetchall()

                # ===== ADD AVATAR COLORS =====
                avatar_colors = [
                    '#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0',
                    '#6610f2', '#6f42c1', '#d63384', '#fd7e14', '#20c997'
                ]

                # Add colors to recent_activities
                for i, activity in enumerate(recent_activities):
                    activity['avatar_color'] = avatar_colors[i % len(avatar_colors)]

                # ===== SIDEBAR STATS =====
                # Get pending users count (inactive users)
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = false")
                pending_users = cur.fetchone()['count'] or 0

                sidebar_stats = {
                    'pending_users': pending_users,
                    'pending_feedback': feedback_stats['pending_feedback']
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
    @admin_required
    def admin_users():
        """Admin - User management with CRUD operations"""
        try:
            # Get page and filters
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            user_type = request.args.get('type', '')
            status = request.args.get('status', '')
            search = request.args.get('search', '')

            with get_db_cursor_readonly() as cur:
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
                    query += " AND is_active = true"
                    count_query += " AND is_active = true"
                elif status == 'inactive':
                    query += " AND is_active = false"
                    count_query += " AND is_active = false"

                if search:
                    query += " AND (username ILIKE %s OR email ILIKE %s OR full_name ILIKE %s)"
                    count_query += " AND (username ILIKE %s OR email ILIKE %s OR full_name ILIKE %s)"
                    search_param = f"%{search}%"
                    params.extend([search_param, search_param, search_param])
                    count_params.extend([search_param, search_param, search_param])

                # Get total count
                cur.execute(count_query, count_params)
                total_users = cur.fetchone()['total'] or 0
                total_pages = (total_users + per_page - 1) // per_page if total_users > 0 else 1

                # Add pagination
                query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
                pagination_params = params + [per_page, offset]

                cur.execute(query, pagination_params)
                users = cur.fetchall()

                # Get statistics for cards
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_users,
                        SUM(CASE WHEN user_type = 'farmer' THEN 1 ELSE 0 END) as farmers,
                        SUM(CASE WHEN user_type = 'expert' THEN 1 ELSE 0 END) as experts,
                        SUM(CASE WHEN user_type = 'researcher' THEN 1 ELSE 0 END) as researchers,
                        SUM(CASE WHEN user_type = 'student' THEN 1 ELSE 0 END) as students,
                        SUM(CASE WHEN user_type = 'admin' THEN 1 ELSE 0 END) as admins,
                        SUM(CASE WHEN DATE(last_login) = CURRENT_DATE THEN 1 ELSE 0 END) as active_today,
                        SUM(CASE WHEN is_active = true THEN 1 ELSE 0 END) as active_users,
                        SUM(CASE WHEN is_active = false THEN 1 ELSE 0 END) as inactive_users
                    FROM users
                """)
                stats = cur.fetchone()

                # Get pending counts
                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()['count'] or 0

                # Get pending diseases count
                try:
                    cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                    pending_diseases = cur.fetchone()['count'] or 0
                except:
                    pending_diseases = 0

                # Get pending reviews count
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()['count'] or 0

                # Create sidebar stats
                sidebar_stats = {
                    'pending_users': stats['inactive_users'] if stats else 0,
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

            # Check if user exists
            with get_db_cursor_readonly() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
                if cur.fetchone():
                    flash('Username or email already exists!', 'danger')
                    return redirect(url_for('admin_users'))

            # Create user
            password_hash = hash_password(password)
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, full_name, user_type, 
                                      phone_number, location, is_active, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, true, NOW())
                    RETURNING id
                """, (username, email, password_hash, full_name, user_type, phone, location))

                user_id = cur.fetchone()['id']

                # Create default settings
                try:
                    cur.execute("""
                        INSERT INTO user_settings (user_id) VALUES (%s)
                    """, (user_id,))
                except:
                    pass  # Settings table might not exist

                # Log activity (if table exists)
                try:
                    cur.execute("""
                        INSERT INTO activity_logs (user_id, action, entity_type, entity_id, ip_address, created_at)
                        VALUES (%s, %s, %s, %s, %s, NOW())
                    """, (session['user_id'], f"Created user: {username}", 'user', user_id, request.remote_addr))
                except:
                    pass

            flash(f'User {username} created successfully!', 'success')

        except IntegrityError:
            flash('Username or email already exists!', 'danger')
        except Exception as e:
            print(f"Create user error: {e}")
            flash('Error creating user', 'danger')

        return redirect(url_for('admin_users'))

    @app.route("/admin/user/<int:user_id>/update", methods=["POST"])
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
    @admin_required
    def admin_toggle_user_status(user_id):
        """Admin - Activate/Deactivate user"""
        try:
            with get_db_cursor_readonly() as cur:
                # Get current status
                cur.execute("SELECT username, is_active FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

                if not user:
                    return jsonify({'success': False, 'error': 'User not found'}), 404

            # Toggle status
            with get_db_cursor() as cur:
                cur.execute("UPDATE users SET is_active = NOT is_active, updated_at = NOW() WHERE id = %s",
                            (user_id,))

            return jsonify({'success': True, 'is_active': not user['is_active']})

        except Exception as e:
            print(f"Toggle user status error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
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
    @admin_required
    def admin_get_user(user_id):
        """API - Get user details"""
        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number as phone, location, profile_image,
                           is_active, created_at, last_login
                    FROM users 
                    WHERE id = %s
                """, (user_id,))

                user = cur.fetchone()

                if not user:
                    return jsonify({'error': 'User not found'}), 404

                # Format dates
                if user['created_at']:
                    user['created_at'] = user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                if user['last_login']:
                    user['last_login'] = user['last_login'].strftime('%Y-%m-%d %H:%M:%S')

            return jsonify(user)

        except Exception as e:
            print(f"Get user error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route("/admin/users/export")
    @admin_required
    def admin_export_users():
        """Admin - Export users to CSV"""
        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number, location, is_active, created_at, last_login
                    FROM users
                    ORDER BY created_at DESC
                """)

                users = cur.fetchall()

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
    @admin_required
    def admin_feedback():
        """Admin view to see all feedback"""
        try:
            # Get filter parameters
            status = request.args.get('status', '')
            category = request.args.get('category', '')
            search = request.args.get('search', '')

            with get_db_cursor_readonly() as cur:
                # Base query
                query = """
                    SELECT f.*, u.username, u.full_name, u.email, u.user_type
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

                cur.execute(query, params)
                feedback_list = cur.fetchall()

                # Get unique categories for filter dropdown
                cur.execute("SELECT DISTINCT feedback_type FROM feedback")
                categories = [row['feedback_type'] for row in cur.fetchall() if row['feedback_type']]

                # Get sidebar stats
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = false")
                pending_users = cur.fetchone()['count'] or 0

                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()['count'] or 0

                # Get pending diseases count
                try:
                    cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                    pending_diseases = cur.fetchone()['count'] or 0
                except:
                    pending_diseases = 0

                # Get pending reviews count
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()['count'] or 0

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
    def admin_get_feedback(feedback_id):
        """Admin - Get feedback details"""
        # Check if user is admin
        if session.get('user_type') != 'admin':
            return jsonify({'error': 'Unauthorized access'}), 401

        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT f.*, u.username, u.full_name, u.email, u.user_type
                    FROM feedback f
                    LEFT JOIN users u ON f.user_id = u.id
                    WHERE f.id = %s
                """, (feedback_id,))

                feedback = cur.fetchone()

                if not feedback:
                    return jsonify({'error': 'Feedback not found'}), 404

                # Format dates
                if feedback['created_at']:
                    feedback['created_at'] = feedback['created_at'].isoformat() if hasattr(feedback['created_at'],
                                                                                           'isoformat') else str(
                        feedback['created_at'])

            return jsonify(feedback)

        except Exception as e:
            print(f"Get feedback error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route("/admin/feedback/<int:feedback_id>/reply", methods=["POST"])
    @login_required
    def admin_reply_feedback(feedback_id):
        """Admin - Reply to feedback - DOES NOT change status"""
        # Check if user is admin
        if session.get('user_type') != 'admin':
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 401

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
    def admin_update_feedback_status(feedback_id):
        """Admin - Manually update feedback status"""
        # Check if user is admin
        if session.get('user_type') != 'admin':
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 401

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

    @app.route('/admin/clean-all-paths')
    @admin_required
    def clean_all_image_paths():
        """Clean up all image paths in database to just filenames"""
        try:
            with get_db_cursor_readonly() as cur:
                # Get all records with image paths
                cur.execute("SELECT id, image_path FROM diagnosis_history WHERE image_path IS NOT NULL")
                records = cur.fetchall()

            updated = 0
            for record in records:
                record_id = record['id']
                image_path = record['image_path']

                if image_path:
                    # Extract just the filename
                    filename = os.path.basename(image_path)

                    # Only update if it's different
                    if filename != image_path:
                        with get_db_cursor() as cur:
                            cur.execute("UPDATE diagnosis_history SET image_path = %s WHERE id = %s",
                                       (filename, record_id))
                        updated += 1
                        print(f"Updated ID {record_id}: {image_path} -> {filename}")

            return f"✅ Cleaned up {updated} records. All image paths are now simple filenames."

        except Exception as e:
            return f"Error: {str(e)}"

    # ========== SETTINGS ROUTES ==========

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        """User settings page with profile management"""
        user_id = session.get('user_id')

        if not user_id:
            return redirect(url_for('login'))

        with get_db_cursor_readonly() as cur:
            # Get user information
            cur.execute("""
                SELECT id, username, email, full_name, phone_number, 
                       location, profile_image, user_type, is_active, 
                       created_at, last_login, bio, language
                FROM users WHERE id = %s
            """, (user_id,))
            user = cur.fetchone()

            if not user:
                return redirect(url_for('login'))

            # Get user settings
            try:
                cur.execute("SELECT * FROM user_settings WHERE user_id = %s", (user_id,))
                settings_data = cur.fetchone()
            except:
                settings_data = None

            # If no settings exist, create default settings
            if not settings_data:
                try:
                    with get_db_cursor() as cur2:
                        cur2.execute("""
                            INSERT INTO user_settings (user_id) VALUES (%s)
                        """, (user_id,))
                except:
                    pass

                # Fetch again
                with get_db_cursor_readonly() as cur3:
                    cur3.execute("SELECT * FROM user_settings WHERE user_id = %s", (user_id,))
                    settings_data = cur3.fetchone()

            # Get account statistics
            cur.execute("""
                SELECT 
                    created_at,
                    last_login,
                    (SELECT COUNT(*) FROM diagnosis_history WHERE user_id = %s) as total_diagnosis,
                    0 as saved_items
                FROM users WHERE id = %s
            """, (user_id, user_id))
            stats = cur.fetchone()

        # Handle form submissions
        if request.method == 'POST':
            form_id = request.form.get('form_id')

            # Account Form
            if form_id == 'accountForm':
                return handle_account_form(user_id, request.form)

            # Profile Form with Image Upload
            elif form_id == 'profileForm':
                return handle_profile_form(user_id, request)

            # Notifications Form
            elif form_id == 'notificationsForm':
                return handle_notifications_form(user_id, request.form)

            # Privacy Form
            elif form_id == 'privacyForm':
                return handle_privacy_form(user_id, request.form)

            # Preferences Form
            elif form_id == 'preferencesForm':
                return handle_preferences_form(user_id, request.form)

        return render_template('settings.html',
                               user=user,
                               settings=settings_data,
                               account_stats=stats)

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
                with get_db_cursor_readonly() as cur2:
                    cur2.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
                    user = cur2.fetchone()

                from auth import check_password_hash
                if user and check_password(user['password_hash'], current_password):
                    if new_password == confirm_password:
                        from auth import hash_password
                        hashed_password = hash_password(new_password)
                        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, user_id))
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
        with get_db_cursor_readonly() as cur:
            cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
            current_user = cur.fetchone()

        # Handle profile image upload
        profile_image = None
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':

                # Check if file is allowed
                ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

                def allowed_file(filename):
                    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

                if allowed_file(file.filename):
                    # Create upload directory if it doesn't exist
                    upload_folder = 'static/uploads/profiles'
                    os.makedirs(upload_folder, exist_ok=True)

                    # Generate secure filename
                    from werkzeug.utils import secure_filename
                    filename = secure_filename(file.filename)
                    # Add timestamp and user_id to prevent duplicates
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    new_filename = f"{user_id}_{timestamp}_{filename}"

                    # Full path to save
                    filepath = os.path.join(upload_folder, new_filename)

                    # Save the file
                    file.save(filepath)

                    # Delete old profile image if exists
                    if current_user and current_user['profile_image']:
                        old_filepath = os.path.join('static/uploads/profiles', current_user['profile_image'])
                        if os.path.exists(old_filepath):
                            try:
                                os.remove(old_filepath)
                            except:
                                pass  # Ignore errors if file doesn't exist

                    # Set new profile image filename
                    profile_image = new_filename
                else:
                    flash('Invalid file type. Please upload JPG, PNG, or GIF.', 'danger')
                    return redirect(url_for('settings') + '#profile')

        # Update user profile
        with get_db_cursor() as cur:
            update_query = """
                UPDATE users 
                SET full_name = %s,
                    phone_number = %s,
                    location = %s,
                    language = %s,
                    bio = %s
            """
            params = [full_name, phone, location, language, bio]

            # Add profile image to update if new image was uploaded
            if profile_image:
                update_query += ", profile_image = %s"
                params.append(profile_image)

            update_query += " WHERE id = %s"
            params.append(user_id)

            cur.execute(update_query, params)

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('settings') + '#profile')

    def handle_notifications_form(user_id, form_data):
        """Handle notifications form submission"""
        # Get checkbox values (checkboxes return 'on' when checked, None when not checked)
        email_notifications = True if form_data.get('email_notifications') == 'on' else False
        email_updates = True if form_data.get('email_updates') == 'on' else False
        email_newsletter = True if form_data.get('email_newsletter') == 'on' else False
        email_promotions = True if form_data.get('email_promotions') == 'on' else False
        app_notifications = True if form_data.get('app_notifications') == 'on' else False
        app_security = True if form_data.get('app_security') == 'on' else False
        app_reminders = True if form_data.get('app_reminders') == 'on' else False
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
        profile_public = True if form_data.get('profile_public') == 'on' else False
        show_diagnosis = True if form_data.get('show_diagnosis') == 'on' else False
        data_collection = True if form_data.get('data_collection') == 'on' else False

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
        auto_save = True if form_data.get('auto_save') == 'on' else False
        show_tips = True if form_data.get('show_tips') == 'on' else False
        detailed_results = True if form_data.get('detailed_results') == 'on' else False
        quick_analysis = True if form_data.get('quick_analysis') == 'on' else False
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

    @app.route("/user_guide")
    @app.route("/how-it-works")
    def user_guide():
        """User guide / How it works page"""
        return render_template("user_guide.html")

    @app.route("/admin/analytics")
    @admin_required
    def admin_analytics():
        """Admin analytics page"""
        try:
            # Get period filter with safe default
            period = request.args.get('period', '30')
            days = int(period) if period and period.isdigit() else 30
            start_date = datetime.now() - timedelta(days=days)

            with get_db_cursor_readonly() as cur:
                # ===== USER DISTRIBUTION =====
                cur.execute("""
                    SELECT 
                        user_type,
                        COUNT(*) as count
                    FROM users
                    GROUP BY user_type
                    ORDER BY count DESC
                """)
                user_distribution = cur.fetchall()

                # ===== DAILY NEW USERS =====
                cur.execute("""
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as new_users
                    FROM users
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, (start_date,))
                user_growth = cur.fetchall()

                # ===== DAILY DIAGNOSES =====
                cur.execute("""
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as diagnoses
                    FROM diagnosis_history
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, (start_date,))
                daily_diagnoses = cur.fetchall()

                # ===== DIAGNOSES BY CROP =====
                cur.execute("""
                    SELECT 
                        crop,
                        COUNT(*) as count,
                        ROUND(AVG(confidence), 1) as avg_confidence
                    FROM diagnosis_history
                    WHERE crop IS NOT NULL AND created_at >= %s
                    GROUP BY crop
                    ORDER BY count DESC
                    LIMIT 10
                """, (start_date,))
                top_crops = cur.fetchall()

                # ===== TOP DISEASES =====
                cur.execute("""
                    SELECT 
                        disease_detected,
                        COUNT(*) as count,
                        ROUND(AVG(confidence), 1) as avg_confidence
                    FROM diagnosis_history
                    WHERE disease_detected != 'Healthy Plant' 
                      AND disease_detected IS NOT NULL
                      AND created_at >= %s
                    GROUP BY disease_detected
                    ORDER BY count DESC
                    LIMIT 10
                """, (start_date,))
                top_diseases = cur.fetchall()

                # Get pending counts for sidebar
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = false")
                pending_users = cur.fetchone()['count'] or 0

                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()['count'] or 0

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
    @admin_required
    def admin_settings():
        """Admin settings page - separate from farmer settings"""
        try:
            with get_db_cursor_readonly() as cur:
                # Get admin user data from users table
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number as phone, location, bio, profile_image,
                           is_active, created_at, last_login
                    FROM users 
                    WHERE id = %s
                """, (session['user_id'],))
                admin = cur.fetchone()

                # Get user settings from user_settings table
                try:
                    cur.execute("""
                        SELECT * FROM user_settings 
                        WHERE user_id = %s
                    """, (session['user_id'],))
                    user_settings = cur.fetchone()
                except:
                    user_settings = None

                # If no settings exist, create default
                if not user_settings:
                    try:
                        with get_db_cursor() as cur2:
                            cur2.execute("""
                                INSERT INTO user_settings (user_id) VALUES (%s)
                            """, (session['user_id'],))
                    except:
                        pass

                    # Fetch again
                    with get_db_cursor_readonly() as cur3:
                        cur3.execute("""
                            SELECT * FROM user_settings 
                            WHERE user_id = %s
                        """, (session['user_id'],))
                        user_settings = cur3.fetchone()

                # Get system statistics for admin
                cur.execute("SELECT COUNT(*) as total FROM users")
                total_users = cur.fetchone()['total']

                cur.execute("SELECT COUNT(*) as total FROM diagnosis_history")
                total_diagnoses = cur.fetchone()['total']

                # Get pending feedback count
                cur.execute("SELECT COUNT(*) as total FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()['total']

                # Get recent admin actions from users table (last login)
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
            email_notifications = True if request.form.get('email_notifications') == 'on' else False
            app_notifications = True if request.form.get('app_notifications') == 'on' else False

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
                    pass

            # Update session
            session['full_name'] = full_name
            session['email'] = email

            flash('Admin profile updated successfully!', 'success')

        except Exception as e:
            print(f"Admin update settings error: {e}")
            flash('Error updating profile', 'danger')

        return redirect(url_for('admin_settings'))

    @app.route("/admin/history")
    @admin_required
    def admin_history():
        """Admin view of all diagnosis history with expert reviews"""
        try:
            # Get filter parameters
            expert_review_status = request.args.get('expert_review_status', '')
            image_processed = request.args.get('image_processed', '')
            final_confidence_level = request.args.get('final_confidence_level', '')
            crop = request.args.get('crop', '')
            farmer = request.args.get('farmer', '')

            page = request.args.get('page', 1, type=int)
            per_page = 20
            offset = (page - 1) * per_page

            with get_db_cursor_readonly() as cur:
                # Base query with farmer info and expert review details
                query = """
                    SELECT 
                        dh.*,
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

                if image_processed:
                    query += " AND dh.image_processed = %s"
                    count_query += " AND dh.image_processed = %s"
                    params.append(image_processed == 'true')
                    count_params.append(image_processed == 'true')

                if final_confidence_level:
                    query += " AND dh.final_confidence_level = %s"
                    count_query += " AND dh.final_confidence_level = %s"
                    params.append(final_confidence_level)
                    count_params.append(final_confidence_level)

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

                # Get total count for pagination
                cur.execute(count_query, count_params)
                total_row = cur.fetchone()
                total = total_row['total'] if total_row else 0
                total_pages = (total + per_page - 1) // per_page if total > 0 else 1

                # Add pagination
                query += " ORDER BY dh.created_at DESC LIMIT %s OFFSET %s"
                params.extend([per_page, offset])

                cur.execute(query, params)
                diagnoses = cur.fetchall()

                # Parse JSON fields for each diagnosis
                for diag in diagnoses:
                    if diag.get('expert_answers'):
                        try:
                            if isinstance(diag['expert_answers'], str):
                                diag['expert_answers_parsed'] = json.loads(diag['expert_answers'])
                            else:
                                diag['expert_answers_parsed'] = diag['expert_answers']
                        except:
                            diag['expert_answers_parsed'] = []

                    if diag.get('expert_summary'):
                        try:
                            if isinstance(diag['expert_summary'], str):
                                diag['expert_summary_parsed'] = json.loads(diag['expert_summary'])
                            else:
                                diag['expert_summary_parsed'] = diag['expert_summary']
                        except:
                            diag['expert_summary_parsed'] = {'notes': diag['expert_summary']}

                # Get statistics with expert_review_status
                cur.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN expert_review_status = 'accurate' THEN 1 ELSE 0 END) as accurate,
                        SUM(CASE WHEN expert_review_status = 'needs correction' THEN 1 ELSE 0 END) as needs_correction,
                        SUM(CASE WHEN expert_review_status = 'reject' THEN 1 ELSE 0 END) as rejected,
                        SUM(CASE WHEN expert_review_status IS NULL OR expert_review_status = 'pending' THEN 1 ELSE 0 END) as pending,
                        ROUND(AVG(confidence), 1) as avg_confidence
                    FROM diagnosis_history
                """)
                stats_row = cur.fetchone()
                stats = stats_row if stats_row else {
                    'total': 0,
                    'accurate': 0,
                    'needs_correction': 0,
                    'rejected': 0,
                    'pending': 0,
                    'avg_confidence': 0
                }

                # Get unique crops for filter
                cur.execute("SELECT DISTINCT crop FROM diagnosis_history WHERE crop IS NOT NULL ORDER BY crop")
                crops = [row['crop'] for row in cur.fetchall()] if cur.rowcount > 0 else []

                # Get sidebar stats
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = false")
                pending_users = cur.fetchone()['count'] or 0

                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()['count'] or 0

                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()['count'] or 0

                sidebar_stats = {
                    'pending_users': pending_users,
                    'pending_feedback': pending_feedback,
                    'pending_diseases': 0,
                    'pending_reviews': pending_reviews
                }

                # Build filters dict for template
                filters = {
                    'expert_review_status': expert_review_status,
                    'image_processed': image_processed,
                    'final_confidence_level': final_confidence_level,
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

    # ========== EXPERT DASHBOARD ==========
    @app.route("/expert/dashboard")
    @expert_required
    def expert_dashboard():
        """Expert dashboard - simplified version"""
        try:
            expert_id = session['user_id']

            with get_db_cursor_readonly() as cur:
                # Get expert basic info from users table
                cur.execute("""
                    SELECT username, full_name, email, profile_image, created_at
                    FROM users WHERE id = %s
                """, (expert_id,))
                expert = cur.fetchone()

                # Get statistics from diagnosis_history
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history")
                total_diagnoses = cur.fetchone()['count'] or 0

                # Get recent diagnoses that need expert attention
                cur.execute("""
                    SELECT dh.*, u.username as farmer_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    ORDER BY dh.created_at DESC
                    LIMIT 10
                """)
                recent_diagnoses = cur.fetchall()

                # Get disease library count
                cur.execute("SELECT COUNT(*) as count FROM disease_info")
                disease_count = cur.fetchone()['count'] or 0

            return render_template("expert/dashboard.html",
                                   expert=expert,
                                   total_diagnoses=total_diagnoses,
                                   disease_count=disease_count,
                                   recent_diagnoses=recent_diagnoses,
                                   now=datetime.now())

        except Exception as e:
            print(f"Expert dashboard error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading dashboard', 'danger')
            return redirect(url_for('dashboard'))

    # ========== EXPERT DISEASE MANAGEMENT ==========
    @app.route("/expert/diseases")
    @expert_required
    def expert_diseases():
        """Expert - Manage disease library"""
        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT id, crop, disease_code, disease_name, cause, 
                           symptoms, organic_treatment, chemical_treatment, 
                           prevention, manual_treatment, created_at
                    FROM disease_info 
                    ORDER BY crop, disease_name
                """)
                diseases = cur.fetchall()

                # Get unique crops for filter
                cur.execute("SELECT DISTINCT crop FROM disease_info ORDER BY crop")
                crops = [row['crop'] for row in cur.fetchall()]

            return render_template("expert/diseases.html",
                                   diseases=diseases,
                                   crops=crops)

        except Exception as e:
            print(f"Expert diseases error: {e}")
            flash('Error loading diseases', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/diseases/add", methods=["POST"])
    @expert_required
    def expert_add_disease():
        """Expert - Add new disease"""
        try:
            # Get form data
            crop = request.form.get('crop')
            disease_code = request.form.get('disease_code')
            disease_name = request.form.get('disease_name')
            cause = request.form.get('cause')
            symptoms = request.form.get('symptoms')
            organic_treatment = request.form.get('organic_treatment')
            chemical_treatment = request.form.get('chemical_treatment')
            prevention = request.form.get('prevention')
            manual_treatment = request.form.get('manual_treatment')

            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO disease_info (
                        crop, disease_code, disease_name, cause, symptoms,
                        organic_treatment, chemical_treatment, prevention, 
                        manual_treatment, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (crop, disease_code, disease_name, cause, symptoms,
                      organic_treatment, chemical_treatment, prevention, manual_treatment))

            flash('Disease added successfully!', 'success')

        except IntegrityError:
            flash('Disease code already exists for this crop!', 'danger')
        except Exception as e:
            print(f"Add disease error: {e}")
            flash('Error adding disease', 'danger')

        return redirect(url_for('expert_diseases'))

    @app.route("/expert/diseases/<int:disease_id>/edit", methods=["POST"])
    @expert_required
    def expert_edit_disease(disease_id):
        """Expert - Edit disease"""
        try:
            # Get form data
            crop = request.form.get('crop')
            disease_code = request.form.get('disease_code')
            disease_name = request.form.get('disease_name')
            cause = request.form.get('cause')
            symptoms = request.form.get('symptoms')
            organic_treatment = request.form.get('organic_treatment')
            chemical_treatment = request.form.get('chemical_treatment')
            prevention = request.form.get('prevention')
            manual_treatment = request.form.get('manual_treatment')

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE disease_info 
                    SET crop = %s, disease_code = %s, disease_name = %s,
                        cause = %s, symptoms = %s, organic_treatment = %s,
                        chemical_treatment = %s, prevention = %s,
                        manual_treatment = %s
                    WHERE id = %s
                """, (crop, disease_code, disease_name, cause, symptoms,
                      organic_treatment, chemical_treatment, prevention,
                      manual_treatment, disease_id))

            flash('Disease updated successfully!', 'success')

        except Exception as e:
            print(f"Edit disease error: {e}")
            flash('Error updating disease', 'danger')

        return redirect(url_for('expert_diseases'))

    @app.route("/expert/diseases/<int:disease_id>/delete", methods=["POST"])
    @login_required
    @expert_required
    def expert_delete_disease(disease_id):
        """Expert - Delete disease"""
        try:
            with get_db_cursor() as cur:
                cur.execute("DELETE FROM disease_info WHERE id = %s", (disease_id,))

            flash('Disease deleted successfully!', 'success')

        except Exception as e:
            print(f"Delete disease error: {e}")
            flash('Error deleting disease', 'danger')

        return redirect(url_for('expert_diseases'))

    # ========== EXPERT DETECTION REVIEW ==========
    @app.route("/expert/views")
    @expert_required
    def expert_pending_reviews():
        """Expert - View pending diagnoses from diagnosis_history"""
        try:
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            with get_db_cursor_readonly() as cur:
                # FIXED: Use expert_review_status = 'pending'
                cur.execute("""
                    SELECT dh.*, u.username as farmer_name, u.full_name as farmer_full_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.expert_review_status = 'pending' OR dh.expert_review_status IS NULL
                    ORDER BY dh.created_at DESC
                    LIMIT %s OFFSET %s
                """, (per_page, offset))
                diagnoses = cur.fetchall()

                # Get total pending count
                cur.execute("""
                    SELECT COUNT(*) as total 
                    FROM diagnosis_history 
                    WHERE expert_review_status = 'pending' OR expert_review_status IS NULL
                """)
                total = cur.fetchone()['total'] or 0
                total_pages = (total + per_page - 1) // per_page if total > 0 else 1

                # Get all diseases for reference
                cur.execute("SELECT id, disease_name, crop FROM disease_info ORDER BY crop, disease_name")
                diseases = cur.fetchall()

            return render_template("expert/pending_reviews.html",
                                   diagnoses=diagnoses,
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   diseases=diseases,
                                   pending_count=total)

        except Exception as e:
            print(f"Pending reviews error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading pending reviews', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/review/<int:diagnosis_id>", methods=["POST"])
    @expert_required
    def expert_review_detection(diagnosis_id):
        """Expert - Review a disease detection"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400

            print(f"Received review data: {data}")

            action = data.get('action')
            expert_notes = data.get('expert_notes', '')
            corrected_disease = data.get('corrected_disease_id')

            # Convert notes to JSON format
            import json
            if not expert_notes or expert_notes.strip() == '':
                expert_notes_json = json.dumps({"notes": "No notes provided"})
            else:
                expert_notes_json = json.dumps({"notes": expert_notes})

            # First, check if the diagnosis exists
            with get_db_cursor_readonly() as cur:
                cur.execute("SELECT id FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
                if not cur.fetchone():
                    return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

            with get_db_cursor() as cur:
                if action == 'accurate':
                    cur.execute("""
                        UPDATE diagnosis_history 
                        SET training_used = 1,
                            expert_summary = %s,
                            for_training = 1,
                            expert_review_status = 'accurate'
                        WHERE id = %s
                    """, (expert_notes_json, diagnosis_id))

                elif action == 'needs correction':
                    # Get the correct disease name
                    with get_db_cursor_readonly() as cur2:
                        cur2.execute("SELECT disease_name FROM disease_info WHERE id = %s", (corrected_disease,))
                        disease_result = cur2.fetchone()

                    if not disease_result:
                        return jsonify({'success': False, 'error': 'Selected disease not found'}), 404

                    correct_disease_name = disease_result['disease_name']

                    cur.execute("""
                        UPDATE diagnosis_history 
                        SET training_used = 1,
                            expert_summary = %s,
                            for_training = 1,
                            expert_review_status = 'needs correction',
                            disease_detected = %s
                        WHERE id = %s
                    """, (expert_notes_json, correct_disease_name, diagnosis_id))

                elif action == 'reject':
                    cur.execute("""
                        UPDATE diagnosis_history 
                        SET training_used = 1,
                            expert_summary = %s,
                            expert_review_status = 'reject',
                            for_training = 0
                        WHERE id = %s
                    """, (expert_notes_json, diagnosis_id))

                else:
                    return jsonify({'success': False, 'error': f'Invalid action: {action}'}), 400

            print(f"Successfully updated diagnosis {diagnosis_id}")
            return jsonify({'success': True})

        except Exception as e:
            print(f"Review error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route("/expert/history")
    @expert_required
    def expert_history():
        """Expert - View review history"""
        try:
            expert_id = session['user_id']
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            # Get filter parameters
            farmer = request.args.get('farmer', '')
            disease = request.args.get('disease', '')
            status = request.args.get('status', '')
            date_from = request.args.get('date_from', '')
            date_to = request.args.get('date_to', '')

            with get_db_cursor_readonly() as cur:
                # Base query with JOIN to users
                query = """
                    SELECT dh.*, u.username as farmer_name, u.full_name as farmer_full_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.training_used = 1
                """
                count_query = """
                    SELECT COUNT(*) as total 
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.training_used = 1
                """
                params = []
                count_params = []

                # APPLY FILTERS - Farmer name search
                if farmer:
                    query += " AND (u.username ILIKE %s OR u.full_name ILIKE %s)"
                    count_query += " AND (u.username ILIKE %s OR u.full_name ILIKE %s)"
                    params.extend([f'%{farmer}%', f'%{farmer}%'])
                    count_params.extend([f'%{farmer}%', f'%{farmer}%'])

                # APPLY FILTERS - Disease filter
                if disease:
                    query += " AND dh.disease_detected ILIKE %s"
                    count_query += " AND dh.disease_detected ILIKE %s"
                    params.append(f'%{disease}%')
                    count_params.append(f'%{disease}%')

                # APPLY FILTERS - Status filter
                if status:
                    if status == 'approved':
                        query += " AND dh.for_training = 1"
                        count_query += " AND dh.for_training = 1"
                    elif status == 'rejected':
                        query += " AND dh.for_training = 0"
                        count_query += " AND dh.for_training = 0"
                    elif status == 'pending':
                        query += " AND (dh.for_training IS NULL OR dh.for_training = 2)"
                        count_query += " AND (dh.for_training IS NULL OR dh.for_training = 2)"

                # APPLY FILTERS - Date from
                if date_from:
                    query += " AND DATE(dh.created_at) >= %s"
                    count_query += " AND DATE(dh.created_at) >= %s"
                    params.append(date_from)
                    count_params.append(date_from)

                # APPLY FILTERS - Date to
                if date_to:
                    query += " AND DATE(dh.created_at) <= %s"
                    count_query += " AND DATE(dh.created_at) <= %s"
                    params.append(date_to)
                    count_params.append(date_to)

                # Add order by and pagination
                query += " ORDER BY dh.created_at DESC LIMIT %s OFFSET %s"
                params.extend([per_page, offset])

                # Execute main query with filters
                cur.execute(query, params)
                reviews = cur.fetchall()

                # Get total count for pagination (with same filters)
                cur.execute(count_query, count_params)
                total = cur.fetchone()['total'] or 0
                total_pages = (total + per_page - 1) // per_page if total > 0 else 1

                # Get statistics (filtered)
                stats_query = """
                    SELECT 
                        COUNT(*) as total_reviews,
                        SUM(CASE WHEN for_training = 1 THEN 1 ELSE 0 END) as approved_count,
                        SUM(CASE WHEN for_training = 0 THEN 1 ELSE 0 END) as rejected_count,
                        SUM(CASE WHEN for_training IS NULL OR for_training = 2 THEN 1 ELSE 0 END) as pending_count
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.training_used = 1
                """
                stats_params = []

                # Apply same filters to stats for consistency
                if farmer:
                    stats_query += " AND (u.username ILIKE %s OR u.full_name ILIKE %s)"
                    stats_params.extend([f'%{farmer}%', f'%{farmer}%'])
                if disease:
                    stats_query += " AND dh.disease_detected ILIKE %s"
                    stats_params.append(f'%{disease}%')
                if date_from:
                    stats_query += " AND DATE(dh.created_at) >= %s"
                    stats_params.append(date_from)
                if date_to:
                    stats_query += " AND DATE(dh.created_at) <= %s"
                    stats_params.append(date_to)

                cur.execute(stats_query, stats_params)
                stats = cur.fetchone()

            return render_template("expert/history.html",
                                   reviews=reviews,
                                   page=page,
                                   total_pages=total_pages,
                                   total_results=total,
                                   stats=stats,
                                   pending_count=get_pending_count(),
                                   request=request)

        except Exception as e:
            print(f"Expert history error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading history', 'danger')
            return redirect(url_for('expert_dashboard'))

    # ========== EXPERT SETTINGS ROUTES ==========

    @app.route("/expert/settings")
    @expert_required
    def expert_settings():
        """Expert settings page"""
        try:
            expert_id = session['user_id']

            with get_db_cursor_readonly() as cur:
                # Get expert data
                cur.execute("""
                    SELECT id, username, email, full_name, user_type, 
                           phone_number as phone, location, bio, profile_image,
                           is_active, created_at, last_login
                    FROM users 
                    WHERE id = %s
                """, (expert_id,))
                expert = cur.fetchone()

                # Get pending count for sidebar
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history")
                pending_count = cur.fetchone()['count'] or 0

            return render_template("expert/settings.html",
                                   user=expert,
                                   pending_count=pending_count,
                                   now=datetime.now())

        except Exception as e:
            print(f"Expert settings error: {e}")
            flash('Error loading settings', 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/settings/update", methods=["POST"])
    @expert_required
    def expert_update_profile():
        """Update expert profile"""
        try:
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            location = request.form.get('location')
            bio = request.form.get('bio')

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE users 
                    SET full_name = %s, email = %s, phone_number = %s, 
                        location = %s, bio = %s, updated_at = NOW()
                    WHERE id = %s
                """, (full_name, email, phone, location, bio, session['user_id']))

            # Update session
            session['full_name'] = full_name
            session['email'] = email

            flash('Profile updated successfully!', 'success')

        except Exception as e:
            print(f"Update profile error: {e}")
            flash('Error updating profile', 'danger')

        return redirect(url_for('expert_settings'))

    @app.route("/expert/change-password", methods=["POST"])
    @expert_required
    def expert_change_password():
        """Change expert password"""
        try:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            # Validation
            if new_password != confirm_password:
                flash('New passwords do not match!', 'danger')
                return redirect(url_for('expert_settings'))

            if len(new_password) < 8:
                flash('Password must be at least 8 characters long!', 'danger')
                return redirect(url_for('expert_settings'))

            with get_db_cursor_readonly() as cur:
                # Get current password hash
                cur.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
                user = cur.fetchone()

            if not user or not check_password(current_password, user['password_hash']):
                flash('Current password is incorrect!', 'danger')
                return redirect(url_for('expert_settings'))

            # Update password
            new_hash = hash_password(new_password)
            with get_db_cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                            (new_hash, session['user_id']))

            flash('Password changed successfully!', 'success')

        except Exception as e:
            print(f"Password change error: {e}")
            flash('Failed to change password!', 'danger')

        return redirect(url_for('expert_settings'))

    @app.route("/expert/profile/upload-image", methods=["POST"])
    @expert_required
    def expert_upload_image():
        """Upload profile image for expert"""
        user_id = session['user_id']

        try:
            if 'profile_image' not in request.files:
                flash('No file uploaded', 'danger')
                return redirect(url_for('expert_settings'))

            file = request.files['profile_image']

            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('expert_settings'))

            # Validate file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            if not allowed_file(file.filename, {'ALLOWED_EXTENSIONS': allowed_extensions}):
                flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF', 'danger')
                return redirect(url_for('expert_settings'))

            # Validate file size (max 2MB)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)

            if file_size > 2 * 1024 * 1024:
                flash('File size must be less than 2MB', 'danger')
                return redirect(url_for('expert_settings'))

            # Get current user to delete old image
            with get_db_cursor_readonly() as cur:
                cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()

            # Delete old image if exists
            if user and user.get('profile_image'):
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', user['profile_image'])
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

            flash('Profile image updated successfully!', 'success')

        except Exception as e:
            print(f"Upload image error: {e}")
            flash('Error uploading image', 'danger')

        return redirect(url_for('expert_settings'))

    # ========== EXPERT QUESTION MANAGEMENT ROUTES ==========

    @app.route("/expert/questions")
    @expert_required
    def expert_questions():
        """Expert - View and manage all questions"""
        try:
            # Get filter parameters from request
            selected_crop = request.args.get('crop', '')
            selected_disease = request.args.get('disease', '')
            selected_category = request.args.get('category', '')

            with get_db_cursor_readonly() as cur:
                # Build the base query
                query = """
                    SELECT q.id, q.crop, q.disease_code, q.question_text, 
                           q.question_category, q.display_order, q.created_at
                    FROM questions q
                    WHERE 1=1
                """
                params = []

                # Add filters if provided
                if selected_crop:
                    query += " AND q.crop = %s"
                    params.append(selected_crop)

                if selected_disease:
                    query += " AND q.disease_code = %s"
                    params.append(selected_disease)

                if selected_category:
                    query += " AND q.question_category = %s"
                    params.append(selected_category)

                # Order by display_order
                query += " ORDER BY q.display_order ASC, q.crop, q.disease_code, q.id"

                # Execute main query
                cur.execute(query, params)
                questions = cur.fetchall()

                # Get unique values for filter dropdowns
                cur.execute("SELECT DISTINCT crop FROM questions WHERE crop IS NOT NULL ORDER BY crop")
                crops = [row['crop'] for row in cur.fetchall()]

                cur.execute(
                    "SELECT DISTINCT disease_code FROM questions WHERE disease_code IS NOT NULL ORDER BY disease_code")
                diseases = [row['disease_code'] for row in cur.fetchall()]

                cur.execute(
                    "SELECT DISTINCT question_category FROM questions WHERE question_category IS NOT NULL ORDER BY question_category")
                categories = [row['question_category'] for row in cur.fetchall()]

                # Get pending count using the helper function
                pending_count = get_pending_count()

            return render_template("expert/questions.html",
                                   questions=questions,
                                   crops=crops,
                                   diseases=diseases,
                                   categories=categories,
                                   selected_crop=selected_crop,
                                   selected_disease=selected_disease,
                                   selected_category=selected_category,
                                   pending_count=pending_count,
                                   now=datetime.now())

        except Exception as e:
            print(f"Expert questions error: {e}")
            flash('Error loading questions: ' + str(e), 'danger')
            return redirect(url_for('expert_dashboard'))

    @app.route("/expert/questions/add", methods=["GET", "POST"])
    @expert_required
    def expert_add_question():
        """Add a new question"""
        if request.method == "GET":
            # Show add form
            try:
                with get_db_cursor_readonly() as cur:
                    # Get existing crops, diseases, and categories for dropdowns
                    cur.execute("SELECT DISTINCT crop FROM questions ORDER BY crop")
                    crops = [row['crop'] for row in cur.fetchall()]

                    cur.execute("SELECT DISTINCT disease_code FROM questions ORDER BY disease_code")
                    diseases = [row['disease_code'] for row in cur.fetchall()]

                    cur.execute("SELECT DISTINCT question_category FROM questions ORDER BY question_category")
                    categories = [row['question_category'] for row in cur.fetchall()]

                    # Get pending count
                    pending_count = get_pending_count()

                return render_template("expert/add_question.html",
                                       crops=crops,
                                       diseases=diseases,
                                       categories=categories,
                                       pending_count=pending_count,
                                       now=datetime.now())
            except Exception as e:
                print(f"Add question form error: {e}")
                flash('Error loading form', 'danger')
                return redirect(url_for('expert_questions'))

        # POST - Process form
        try:
            crop = request.form.get('crop')
            disease_code = request.form.get('disease_code')
            question_text = request.form.get('question_text')
            question_category = request.form.get('question_category')
            display_order = request.form.get('display_order', 0)

            # Validate
            if not all([crop, disease_code, question_text, question_category]):
                flash('All fields are required', 'danger')
                return redirect(url_for('expert_add_question'))

            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO questions 
                    (crop, disease_code, question_text, question_category, display_order, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (crop, disease_code, question_text, question_category, display_order))

            flash('Question added successfully!', 'success')
            return redirect(url_for('expert_questions'))

        except Exception as e:
            print(f"Add question error: {e}")
            flash('Error adding question', 'danger')
            return redirect(url_for('expert_add_question'))

    @app.route("/expert/questions/edit/<int:question_id>", methods=["GET", "POST"])
    @expert_required
    def expert_edit_question(question_id):
        """Edit an existing question"""
        try:
            if request.method == "GET":
                with get_db_cursor_readonly() as cur:
                    # Get question details
                    cur.execute("SELECT * FROM questions WHERE id = %s", (question_id,))
                    question = cur.fetchone()

                    if not question:
                        flash('Question not found', 'danger')
                        return redirect(url_for('expert_questions'))

                    # Get existing crops, diseases, and categories for dropdowns
                    cur.execute("SELECT DISTINCT crop FROM questions WHERE crop IS NOT NULL ORDER BY crop")
                    crops = [row['crop'] for row in cur.fetchall()]

                    cur.execute(
                        "SELECT DISTINCT disease_code FROM questions WHERE disease_code IS NOT NULL ORDER BY disease_code")
                    diseases = [row['disease_code'] for row in cur.fetchall()]

                    cur.execute(
                        "SELECT DISTINCT question_category FROM questions WHERE question_category IS NOT NULL ORDER BY question_category")
                    categories = [row['question_category'] for row in cur.fetchall()]

                    # Get pending count
                    pending_count = get_pending_count()

                return render_template("expert/edit_question.html",
                                       question=question,
                                       crops=crops,
                                       diseases=diseases,
                                       categories=categories,
                                       pending_count=pending_count,
                                       now=datetime.now())

            # POST - Update question
            crop = request.form.get('crop')
            disease_code = request.form.get('disease_code')
            question_text = request.form.get('question_text')
            question_category = request.form.get('question_category')
            display_order = request.form.get('display_order', 0)

            # Validate required fields
            if not all([crop, disease_code, question_text, question_category]):
                flash('All required fields must be filled out!', 'danger')
                return redirect(url_for('expert_edit_question', question_id=question_id))

            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE questions 
                    SET crop = %s, 
                        disease_code = %s, 
                        question_text = %s, 
                        question_category = %s, 
                        display_order = %s
                    WHERE id = %s
                """, (crop, disease_code, question_text, question_category, display_order, question_id))

            flash('Question updated successfully!', 'success')
            return redirect(url_for('expert_questions'))

        except Exception as e:
            print(f"Edit question error: {e}")
            flash(f'Error updating question: {str(e)}', 'danger')
            return redirect(url_for('expert_edit_question', question_id=question_id))

    @app.route("/expert/questions/delete/<int:question_id>", methods=["POST"])
    @expert_required
    def expert_delete_question(question_id):
        """Delete a question"""
        try:
            with get_db_cursor() as cur:
                cur.execute("DELETE FROM questions WHERE id = %s", (question_id,))

            flash('Question deleted successfully!', 'success')

        except Exception as e:
            print(f"Delete question error: {e}")
            flash('Error deleting question', 'danger')

        return redirect(url_for('expert_questions'))

    @app.route('/expert/review/<int:diagnosis_id>', methods=['POST'])
    @expert_required
    def expert_submit_review(diagnosis_id):
        """Submit a review for a diagnosis"""
        try:
            data = request.get_json()
            print(f"Received review data: {data}")

            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400

            action = data.get('action')
            expert_notes = data.get('expert_notes', '')

            # Get corrected disease info if provided
            corrected_disease_id = data.get('corrected_disease_id')
            corrected_disease_name = data.get('corrected_disease_name')

            # Validate the action
            valid_actions = ['accurate', 'needs correction', 'reject']
            if action not in valid_actions:
                print(f"Invalid action: '{action}'")
                return jsonify({
                    'success': False,
                    'error': f'Invalid action: {action}. Must be one of: {", ".join(valid_actions)}'
                }), 400

            # Set for_training flag based on action
            for_training = 1 if action == 'accurate' else 0

            # Prepare expert summary JSON
            expert_summary = {
                'notes': expert_notes,
                'reviewed_at': datetime.now().isoformat(),
                'reviewed_by': session.get('username'),
                'reviewed_by_id': session.get('user_id'),
                'action': action,
                'original_diagnosis_id': diagnosis_id
            }

            # Add corrected disease info if provided
            if corrected_disease_id and corrected_disease_name:
                expert_summary['corrected_disease'] = {
                    'id': corrected_disease_id,
                    'name': corrected_disease_name
                }

            # Convert to JSON string for storage
            expert_summary_json = json.dumps(expert_summary)

            # First, get the original diagnosis data
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT user_id, crop, disease_detected, confidence, symptoms, 
                           recommendations, image_path
                    FROM diagnosis_history 
                    WHERE id = %s
                """, (diagnosis_id,))
                original_diagnosis = cur.fetchone()

            if not original_diagnosis:
                return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

            # Update the diagnosis with review information
            with get_db_cursor() as cur:
                cur.execute("""
                    UPDATE diagnosis_history 
                    SET expert_review_status = %s,
                        training_used = 1,
                        for_training = %s,
                        expert_summary = %s,
                        reviewed_at = NOW(),
                        reviewed_by = %s
                    WHERE id = %s
                """, (action, for_training, expert_summary_json, session['user_id'], diagnosis_id))

            print(f"✅ Successfully updated diagnosis {diagnosis_id}")

            # If this was a correction, create a new corrected record for training
            if action == 'needs correction' and corrected_disease_id and corrected_disease_name:
                try:
                    with get_db_cursor() as cur:
                        cur.execute("""
                            INSERT INTO diagnosis_history 
                            (user_id, crop, disease_detected, confidence, symptoms, recommendations, 
                             expert_review_status, for_training, image_path, created_at,
                             expert_summary)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
                        """, (
                            original_diagnosis['user_id'],
                            original_diagnosis['crop'],
                            corrected_disease_name,
                            100.00,
                            original_diagnosis['symptoms'],
                            original_diagnosis['recommendations'],
                            'accurate',
                            1,
                            original_diagnosis['image_path'],
                            json.dumps({
                                'corrected_from': diagnosis_id,
                                'corrected_by': session.get('username'),
                                'correction_notes': expert_notes,
                                'corrected_at': datetime.now().isoformat()
                            })
                        ))
                    print(f"✅ Created corrected diagnosis record for training")

                except Exception as e:
                    print(f"Warning: Could not create corrected record: {e}")
                    # Don't fail the main request if this fails

            return jsonify({
                'success': True,
                'message': 'Review submitted successfully',
                'expert_review_status': action
            })

        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/expert/disease-library')
    @login_required
    @expert_required
    def expert_disease_library():
        """Display disease library page for experts"""
        try:
            crop = request.args.get('crop', 'corn')  # Default to 'corn'
            if crop not in ['corn', 'rice']:
                crop = 'corn'

            page = request.args.get('page', 1, type=int)
            per_page = 12
            offset = (page - 1) * per_page

            with get_db_cursor_readonly() as cur:
                # Get total count for pagination
                cur.execute("""
                    SELECT COUNT(*) as total 
                    FROM disease_info 
                    WHERE crop = %s
                """, (crop,))
                total_result = cur.fetchone()
                total = total_result['total'] if total_result else 0

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

                diseases = cur.fetchall()

                # Get sample images for each disease
                for disease in diseases:
                    sample_cursor = db.cursor(dictionary=True)
                    sample_cursor.execute("""
                        SELECT 
                            id,
                            image_title as title,
                            severity_level as severity,
                            display_order
                        FROM disease_samples 
                        WHERE crop = %s AND disease_code = %s
                        ORDER BY display_order
                        LIMIT 1
                    """, (crop, disease['disease_code']))

                    first_sample = sample_cursor.fetchone()

                    if first_sample:
                        disease['sample_image'] = url_for('get_disease_sample_image',
                                                          sample_id=first_sample['id'],
                                                          _external=False)
                    else:
                        disease['sample_image'] = None

                crop_display = 'Corn' if crop == 'corn' else 'Rice'

                # Create pagination object
                class SimplePagination:
                    def __init__(self, page, per_page, total):
                        self.page = page
                        self.per_page = per_page
                        self.total = total
                        self.pages = (total + per_page - 1) // per_page if total > 0 else 1
                        self.has_prev = page > 1
                        self.has_next = page < self.pages
                        self.prev_num = page - 1
                        self.next_num = page + 1

                    def iter_pages(self, left_edge=2, left_current=2,
                                   right_current=2, right_edge=2):
                        last = 0
                        for num in range(1, self.pages + 1):
                            if num <= left_edge or \
                                    (num >= self.page - left_current and num <= self.page + right_current) or \
                                    num > self.pages - right_edge:
                                if last + 1 != num:
                                    yield None
                                yield num
                                last = num

                pagination = SimplePagination(page, per_page, total)

                # Get pending count for sidebar
                pending_count = get_pending_count()

            return render_template(
                'expert/diseases.html',
                diseases=diseases,
                crop=crop,
                crop_display=crop_display,
                pagination=pagination,
                pending_count=pending_count
            )

        except Exception as e:
            print(f"Expert diseases error: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Error loading disease library: {str(e)}', 'danger')
            return redirect(url_for('expert_dashboard'))

    # For the diagnosis details endpoint
    @app.route("/api/diagnosis/<int:id>")
    @expert_required
    def get_diagnosis_api(id):
        """Get diagnosis details for review modal"""
        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT dh.*, u.username as farmer_name, u.full_name as farmer_full_name
                    FROM diagnosis_history dh
                    JOIN users u ON dh.user_id = u.id
                    WHERE dh.id = %s
                """, (id,))

                diagnosis = cur.fetchone()

                if not diagnosis:
                    return jsonify({'error': 'Diagnosis not found'}), 404

                # Format dates for JSON serialization
                if diagnosis.get('created_at'):
                    diagnosis['created_at'] = diagnosis['created_at'].isoformat()
                if diagnosis.get('reviewed_at'):
                    diagnosis['reviewed_at'] = diagnosis['reviewed_at'].isoformat()

                print(f"API returning diagnosis {id} with image_path: {diagnosis.get('image_path')}")

            return jsonify(diagnosis)

        except Exception as e:
            print(f"Error fetching diagnosis: {e}")
            return jsonify({'error': str(e)}), 500

    # For the image endpoint
    @app.route('/api/diagnosis/<int:diagnosis_id>/image')
    @expert_required
    def api_get_diagnosis_image(diagnosis_id):
        """Retrieve and display the diagnosis image from filesystem"""
        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("SELECT image_path FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
                result = cur.fetchone()

            if not result or not result['image_path']:
                return send_file('static/img/no-image.png', mimetype='image/png')

            image_path = result['image_path']

            # Construct full path
            app_dir = os.path.dirname(os.path.abspath(__file__))
            if os.path.isabs(image_path):
                full_path = image_path
            elif image_path.startswith('static/'):
                full_path = os.path.join(app_dir, image_path)
            elif image_path.startswith('uploads/'):
                full_path = os.path.join(app_dir, 'static', image_path)
            else:
                full_path = os.path.join(app_dir, 'static', 'uploads', image_path)

            if os.path.exists(full_path):
                return send_file(full_path)
            else:
                return send_file('static/img/no-image.png', mimetype='image/png')

        except Exception as e:
            print(f"Error retrieving image: {e}")
            return send_file('static/img/error-image.png', mimetype='image/png')

    # ==================== UPLOAD ROUTES ====================
    def allowed_file(filename):
        """Check if file extension is allowed"""
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    @app.route('/api/upload-disease-image', methods=['POST'])
    @login_required
    @expert_required
    def upload_disease_image():
        """Upload an image for a disease - stores in filesystem, not BLOB"""
        print("=" * 50)
        print("UPLOAD DISEASE IMAGE CALLED")
        print("=" * 50)

        try:
            if 'image' not in request.files:
                return jsonify({'success': False, 'message': 'No image file provided'}), 400

            file = request.files['image']

            if file.filename == '':
                return jsonify({'success': False, 'message': 'No file selected'}), 400

            # Check file size (limit to 16MB)
            file.seek(0, 2)
            file_size = file.tell()
            file.seek(0)

            if file_size > 16 * 1024 * 1024:  # 16MB limit
                return jsonify({'success': False, 'message': 'File too large. Maximum size is 16MB.'}), 400

            if not allowed_file(file.filename):
                return jsonify(
                    {'success': False, 'message': 'File type not allowed. Please upload JPG, PNG, or GIF'}), 400

            # Get form data
            disease_code = request.form.get('disease_code', '')
            crop = request.form.get('crop', 'corn')
            severity = request.form.get('severity_level', 'Moderate')
            image_title = request.form.get('image_title', file.filename)
            image_description = request.form.get('image_description', '')
            sample_id = request.form.get('sample_id')

            # Validate
            if not sample_id and not disease_code:
                return jsonify({'success': False, 'message': 'Disease code is required for new samples'}), 400

            # Save file to filesystem
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(f"{crop}_{disease_code}_{timestamp}_{file.filename}")
            upload_folder = os.path.join('static', 'uploads', 'disease_samples')
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            # Store relative path in database
            relative_path = os.path.join('uploads', 'disease_samples', filename)

            with get_db_cursor() as cur:
                if sample_id:
                    # Update existing sample
                    cur.execute("""
                        UPDATE disease_samples 
                        SET image_path = %s, image_title = %s, image_description = %s, severity_level = %s
                        WHERE id = %s
                    """, (relative_path, image_title, image_description, severity, sample_id))
                    new_sample_id = sample_id
                    message = 'Sample updated successfully'
                else:
                    # Get next display order
                    cur.execute("""
                        SELECT COALESCE(MAX(display_order), 0) + 1 as next_order
                        FROM disease_samples 
                        WHERE crop = %s AND disease_code = %s
                    """, (crop, disease_code))
                    result = cur.fetchone()
                    next_order = result['next_order'] if result else 1

                    # Insert new sample
                    cur.execute("""
                        INSERT INTO disease_samples (
                            crop, disease_code, image_path, image_title, 
                            image_description, severity_level, display_order, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                        RETURNING id
                    """, (crop, disease_code, relative_path, image_title, image_description, severity, next_order))

                    new_sample_id = cur.fetchone()['id']
                    message = 'Image uploaded successfully'

            # Generate image URL
            image_url = url_for('static', filename=relative_path)

            print(f"✅ Upload successful: sample_id={new_sample_id}")

            return jsonify({
                'success': True,
                'sample_id': new_sample_id,
                'message': message,
                'image_url': image_url
            })

        except Exception as e:
            print(f"❌ Unexpected error in upload_disease_image: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Unexpected error: {str(e)}'}), 500

    # ==================== DISEASE API ROUTES ====================

    @app.route('/api/disease', methods=['POST'])
    @login_required
    @expert_required
    def add_disease():
        """Add new disease to disease_info table"""
        try:
            data = request.json

            # Validate required fields
            required = ['disease_code', 'crop', 'cause', 'symptoms']
            for field in required:
                if not data.get(field):
                    return jsonify({'success': False, 'message': f'{field} is required'}), 400

            with get_db_cursor_readonly() as cur:
                # Check if disease code exists
                cur.execute(
                    "SELECT id FROM disease_info WHERE disease_code = %s AND crop = %s",
                    (data['disease_code'], data['crop'])
                )
                if cur.fetchone():
                    return jsonify({'success': False, 'message': 'Disease code already exists'}), 400

            with get_db_cursor() as cur:
                # Insert into disease_info
                cur.execute("""
                    INSERT INTO disease_info (
                        disease_code, crop, cause, symptoms,
                        organic_treatment, chemical_treatment, prevention, manual_treatment,
                        created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    RETURNING id
                """, (
                    data['disease_code'],
                    data['crop'],
                    data['cause'],
                    data['symptoms'],
                    data.get('organic_treatment'),
                    data.get('chemical_treatment'),
                    data.get('prevention'),
                    data.get('manual_treatment')
                ))

                disease_id = cur.fetchone()['id']

                # If sample image provided, add to disease_samples
                if data.get('sample_image'):
                    cur.execute("""
                        INSERT INTO disease_samples (
                            disease_code, crop, image_path, 
                            severity_level, display_order, created_at
                        ) VALUES (%s, %s, %s, %s, %s, NOW())
                    """, (
                        data['disease_code'],
                        data['crop'],
                        data['sample_image'],
                        data.get('severity_level', 'Early'),
                        1
                    ))

            return jsonify({'success': True, 'id': disease_id, 'message': 'Disease added successfully'}), 201

        except Exception as e:
            print(f"Error adding disease: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease/<string:disease_code>', methods=['GET'])
    @login_required
    def get_disease(disease_code):
        """Get disease by disease_code from disease_info with sample images"""
        try:
            crop = request.args.get('crop', 'corn')

            with get_db_cursor_readonly() as cur:
                # Get disease info
                cur.execute("""
                    SELECT * FROM disease_info 
                    WHERE crop = %s AND disease_code = %s
                """, (crop, disease_code))

                disease = cur.fetchone()

                if not disease:
                    return jsonify({'success': False, 'message': 'Disease not found'}), 404

                # Get sample images
                cur.execute("""
                    SELECT id, image_path, image_title, image_description, severity_level, display_order
                    FROM disease_samples 
                    WHERE crop = %s AND disease_code = %s
                    ORDER BY display_order
                """, (crop, disease_code))

                samples = cur.fetchall()

                # For each sample, create an image URL
                for sample in samples:
                    if sample['image_path']:
                        sample['image_url'] = url_for('static', filename=sample['image_path'])
                    else:
                        sample['image_url'] = None

                disease['samples'] = samples

            return jsonify({'success': True, 'disease': disease})

        except Exception as e:
            print(f"Error in get_disease: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease/<string:disease_code>', methods=['PUT'])
    @login_required
    @expert_required
    def update_disease(disease_code):
        """Update disease in disease_info table"""
        try:
            data = request.json
            crop = data.get('crop', 'corn')

            with get_db_cursor() as cur:
                # Check if disease exists
                cur.execute(
                    "SELECT id FROM disease_info WHERE crop = %s AND disease_code = %s",
                    (crop, disease_code)
                )
                if not cur.fetchone():
                    return jsonify({'success': False, 'message': 'Disease not found'}), 404

                # Update disease_info
                cur.execute("""
                    UPDATE disease_info 
                    SET cause = %s,
                        symptoms = %s,
                        organic_treatment = %s,
                        chemical_treatment = %s,
                        prevention = %s,
                        manual_treatment = %s
                    WHERE crop = %s AND disease_code = %s
                """, (
                    data.get('cause'),
                    data.get('symptoms'),
                    data.get('organic_treatment'),
                    data.get('chemical_treatment'),
                    data.get('prevention'),
                    data.get('manual_treatment'),
                    crop,
                    disease_code
                ))

                # Update first sample's image if provided
                if data.get('sample_image'):
                    cur.execute("""
                        UPDATE disease_samples 
                        SET image_path = %s
                        WHERE crop = %s AND disease_code = %s 
                        ORDER BY display_order LIMIT 1
                    """, (
                        data['sample_image'],
                        crop,
                        disease_code
                    ))

            return jsonify({'success': True, 'message': 'Disease updated successfully'})

        except Exception as e:
            print(f"Error updating disease: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease/<string:disease_code>', methods=['DELETE'])
    @login_required
    @expert_required
    def delete_disease(disease_code):
        """Delete disease from both tables"""
        try:
            crop = request.args.get('crop', 'corn')

            with get_db_cursor() as cur:
                # First delete from disease_samples
                cur.execute(
                    "DELETE FROM disease_samples WHERE crop = %s AND disease_code = %s",
                    (crop, disease_code)
                )

                # Then delete from disease_info
                cur.execute(
                    "DELETE FROM disease_info WHERE crop = %s AND disease_code = %s",
                    (crop, disease_code)
                )

                if cur.rowcount == 0:
                    return jsonify({'success': False, 'message': 'Disease not found'}), 404

            return jsonify({'success': True, 'message': 'Disease deleted successfully'})

        except Exception as e:
            print(f"Error deleting disease: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease-info', methods=['GET'])
    def disease_info():
        """Get disease info for display from disease_info table"""
        try:
            crop = request.args.get('crop')
            disease_code = request.args.get('disease')

            if not crop or not disease_code:
                return jsonify({'success': False, 'message': 'Missing parameters'}), 400

            with get_db_cursor_readonly() as cur:
                # Get disease info
                cur.execute("""
                    SELECT * FROM disease_info 
                    WHERE crop = %s AND disease_code = %s
                """, (crop, disease_code))

                disease = cur.fetchone()

                if not disease:
                    return jsonify({'success': False, 'message': 'Disease not found'}), 404

                # Get all sample images
                cur.execute("""
                    SELECT 
                        id,
                        image_path,
                        image_title as title,
                        severity_level as severity,
                        display_order
                    FROM disease_samples 
                    WHERE crop = %s AND disease_code = %s
                    ORDER BY display_order
                """, (crop, disease_code))

                samples = cur.fetchall()

                # Create image URLs for each sample
                for sample in samples:
                    if sample['image_path']:
                        sample['url'] = url_for('static', filename=sample['image_path'])
                    else:
                        sample['url'] = None

                # Use disease_code as display name
                display_name = f"Disease {disease_code.replace('_', ' ').title()}"

            return jsonify({
                'success': True,
                'disease_name': display_name,
                'crop_display': 'Corn' if crop == 'corn' else 'Rice',
                'cause': disease['cause'] or 'Information not available',
                'symptoms': disease['symptoms'] or 'See sample images for symptoms',
                'organic_treatment': disease['organic_treatment'] or 'Contact local agricultural expert',
                'chemical_treatment': disease['chemical_treatment'] or 'Contact local agricultural expert',
                'prevention': disease['prevention'] or 'Regular monitoring and early detection',
                'manual_treatment': disease['manual_treatment'] or '',
                'image_url': samples[0]['url'] if samples else None,
                'sample_images': samples,
                'last_updated': disease['created_at']
            })

        except Exception as e:
            print(f"Error in disease_info: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': str(e)}), 500

    class SimplePagination:
        def __init__(self, page, per_page, total):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page if total > 0 else 1
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1
            self.next_num = page + 1

        def iter_pages(self, left_edge=2, left_current=2,
                       right_current=2, right_edge=2):
            last = 0
            for num in range(1, self.pages + 1):
                if num <= left_edge or \
                        (num >= self.page - left_current and num <= self.page + right_current) or \
                        num > self.pages - right_edge:
                    if last + 1 != num:
                        yield None
                    yield num
                    last = num

    @app.route('/api/disease-sample-image/<int:sample_id>')
    @login_required
    def get_disease_sample_image(sample_id):
        """Serve disease sample image from filesystem"""
        try:
            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT image_path, image_title 
                    FROM disease_samples 
                    WHERE id = %s
                """, (sample_id,))

                result = cur.fetchone()

            if not result or not result['image_path']:
                return send_file('static/img/no-image.png', mimetype='image/png')

            image_path = result['image_path']

            # Construct full path
            app_dir = os.path.dirname(os.path.abspath(__file__))
            if os.path.isabs(image_path):
                full_path = image_path
            elif image_path.startswith('static/'):
                full_path = os.path.join(app_dir, image_path)
            else:
                full_path = os.path.join(app_dir, 'static', image_path)

            if os.path.exists(full_path):
                return send_file(full_path)
            else:
                return send_file('static/img/no-image.png', mimetype='image/png')

        except Exception as e:
            print(f"Error retrieving disease sample image: {e}")
            return send_file('static/img/error-image.png', mimetype='image/png')

    @app.route('/api/disease-sample/<int:sample_id>', methods=['PUT'])
    @login_required
    @expert_required
    def update_disease_sample(sample_id):
        """Update sample metadata (not the image itself)"""
        try:
            data = request.json
            if not data:
                return jsonify({'success': False, 'message': 'No data provided'}), 400

            with get_db_cursor() as cur:
                update_fields = []
                values = []

                # Update only metadata fields
                for field in ['image_title', 'image_description', 'severity_level']:
                    if field in data:
                        update_fields.append(f"{field} = %s")
                        values.append(data[field])

                if not update_fields:
                    return jsonify({'success': False, 'message': 'No fields to update'}), 400

                values.append(sample_id)
                cur.execute(f"UPDATE disease_samples SET {', '.join(update_fields)} WHERE id = %s", values)

            return jsonify({'success': True, 'message': 'Sample updated successfully'})

        except Exception as e:
            print(f"Error updating sample: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease/<string:disease_code>/samples', methods=['POST'])
    @login_required
    @expert_required
    def add_sample(disease_code):
        """Add a new sample image for a disease"""
        try:
            data = request.json
            crop = data.get('crop', 'corn')
                        image_path = data.get('image_path')  # Path to already uploaded image

            with get_db_cursor() as cur:
                # Get max display order
                cur.execute("""
                    SELECT COALESCE(MAX(display_order), 0) + 1 as next_order
                    FROM disease_samples 
                    WHERE crop = %s AND disease_code = %s
                """, (crop, disease_code))
                result = cur.fetchone()
                next_order = result['next_order'] if result else 1

                cur.execute("""
                    INSERT INTO disease_samples (
                        disease_code, crop, image_path, image_title,
                        severity_level, display_order, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    RETURNING id
                """, (
                    disease_code,
                    crop,
                    image_path,
                    data.get('image_title', ''),
                    data.get('severity_level', 'Moderate'),
                    next_order
                ))

                sample_id = cur.fetchone()['id']

            return jsonify({
                'success': True,
                'id': sample_id,
                'image_url': url_for('static', filename=image_path) if image_path else None,
                'message': 'Sample added successfully'
            }), 201

        except Exception as e:
            print(f"Error adding sample: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease-sample/<int:sample_id>', methods=['DELETE'])
    @login_required
    @expert_required
    def delete_disease_sample(sample_id):
        """Delete a disease sample"""
        try:
            with get_db_cursor() as cur:
                cur.execute("DELETE FROM disease_samples WHERE id = %s", (sample_id,))

            return jsonify({'success': True, 'message': 'Sample deleted successfully'})

        except Exception as e:
            print(f"Error deleting sample: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

    # ========== ADMIN DISEASE LIBRARY ==========
    @app.route("/admin/disease-library")
    @login_required
    @admin_required
    def admin_disease_library():
        try:
            crop = request.args.get('crop', 'corn')
            page = request.args.get('page', 1, type=int)
            per_page = 12

            offset = (page - 1) * per_page

            with get_db_cursor_readonly() as cur:
                cur.execute("""
                    SELECT 
                        di.*,
                        (SELECT COUNT(*) FROM disease_samples 
                         WHERE disease_code = di.disease_code AND crop = di.crop) as sample_count
                    FROM disease_info di
                    WHERE di.crop = %s
                    ORDER BY di.disease_code
                    LIMIT %s OFFSET %s
                """, (crop, per_page, offset))
                diseases = cur.fetchall()

                cur.execute("SELECT COUNT(*) as total FROM disease_info WHERE crop = %s", (crop,))
                total = cur.fetchone()['total'] or 0

                # For each disease, get sample count but NOT image_path
                for disease in diseases:
                    cur.execute("""
                        SELECT id, image_path
                        FROM disease_samples 
                        WHERE crop = %s AND disease_code = %s 
                        ORDER BY display_order LIMIT 1
                    """, (crop, disease['disease_code']))
                    sample = cur.fetchone()
                    if sample and sample['image_path']:
                        disease['sample_image'] = url_for('static', filename=sample['image_path'])
                    else:
                        disease['sample_image'] = None

                # Get crop statistics
                cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'corn'")
                corn_count = cur.fetchone()['count'] or 0
                cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'rice'")
                rice_count = cur.fetchone()['count'] or 0
                crop_stats = {'corn_count': corn_count, 'rice_count': rice_count}

                # Get sidebar stats
                cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = false")
                pending_users = cur.fetchone()['count'] or 0
                cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
                pending_feedback = cur.fetchone()['count'] or 0
                cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
                pending_reviews = cur.fetchone()['count'] or 0
                try:
                    cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                    pending_diseases = cur.fetchone()['count'] or 0
                except:
                    pending_diseases = 0

            crop_display = 'Corn' if crop == 'corn' else 'Rice'

            # Create pagination object
            class SimplePagination:
                def __init__(self, page, per_page, total):
                    self.page = page
                    self.per_page = per_page
                    self.total = total
                    self.pages = (total + per_page - 1) // per_page if total > 0 else 1
                    self.has_prev = page > 1
                    self.has_next = page < self.pages
                    self.prev_num = page - 1
                    self.next_num = page + 1

                def iter_pages(self, left_edge=2, left_current=2, right_current=2, right_edge=2):
                    last = 0
                    for num in range(1, self.pages + 1):
                        if num <= left_edge or \
                                (num >= self.page - left_current and num <= self.page + right_current) or \
                                num > self.pages - right_edge:
                            if last + 1 != num:
                                yield None
                            yield num
                            last = num

            pagination = SimplePagination(page, per_page, total)

            sidebar_stats = {
                'pending_users': pending_users,
                'pending_feedback': pending_feedback,
                'pending_diseases': pending_diseases,
                'pending_reviews': pending_reviews
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

    # ========== HELPER FUNCTION ==========

    @app.context_processor
    def inject_pending_count():
        """Make pending_count available to all expert templates automatically"""
        if session.get('user_type') == 'expert':
            try:
                with get_db_cursor_readonly() as cur:
                    cur.execute(
                        "SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending' OR expert_review_status IS NULL")
                    result = cur.fetchone()
                    count = result['count'] if result else 0
                    return {'pending_count': count}
            except Exception as e:
                print(f"Error getting pending count: {e}")
                return {'pending_count': 0}
        return {'pending_count': 0}

    def save_diagnosis_to_history(user_id, crop, disease_detected, confidence,
                                  image_path, symptoms, recommendations, location=None):
        """Save diagnosis to history table"""
        try:
            with get_db_cursor() as cur:
                cur.execute("""
                    INSERT INTO diagnosis_history 
                    (user_id, crop, disease_detected, confidence, image_path, 
                     symptoms, recommendations, location)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (user_id, crop, disease_detected, confidence, image_path,
                      symptoms, recommendations, location or session.get('location')))

                result = cur.fetchone()
                return result['id'] if result else None

        except Exception as e:
            print(f"Error saving diagnosis to history: {e}")
            return None

    return app