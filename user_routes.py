# user_routes.py (import this in your main app.py)
import json

from flask import render_template, request, session, redirect, url_for, flash, jsonify, Response, make_response, \
    send_file

from db_config import get_db
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
        db = None
        cur = None
        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

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
        finally:
            if cur: cur.close()
            if db: db.close()

    # ========== AUTHENTICATION ROUTES ==========

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """User registration"""
        db = None
        cur = None

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

                db = get_db()
                cur = db.cursor(dictionary=True)

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
                """, (username, email, password_hash, full_name, user_type, phone, location))

                user_id = cur.lastrowid

                # Create default settings
                cur.execute("""
                    INSERT INTO user_settings (user_id) VALUES (%s)
                """, (user_id,))

                # Create subscription if newsletter is checked
                newsletter = request.form.get('newsletter') == 'on'
                if newsletter:
                    cur.execute("""
                        INSERT INTO user_subscriptions (user_id, newsletter) 
                        VALUES (%s, TRUE)
                    """, (user_id,))

                db.commit()

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
            flash('Registration failed. Please try again.', 'danger')
            return render_template("register.html", redirect_to=redirect_to)
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

        # GET request - show registration form
        return render_template("register.html", redirect_to=redirect_to)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User login"""
        db = None
        cur = None

        try:
            # If already logged in, redirect based on role
            if 'user_id' in session:
                if session.get('user_type') == 'admin':
                    print("🔄 Already logged in as admin, redirecting to admin dashboard")
                    return redirect(url_for('admin_dashboard'))  # FIXED: no slash
                elif session.get('user_type') == 'expert':
                    print("🔄 Already logged in as expert, redirecting to expert dashboard")
                    return redirect(url_for('expert_dashboard'))  # FIXED: no slash
                else:
                    return redirect(url_for('dashboard'))

            # Handle POST request
            if request.method == "POST":
                username = request.form.get('username')
                password = request.form.get('password')
                remember = request.form.get('remember') == 'on'

                print(f"🔐 Login attempt for: {username}")

                db = get_db()
                cur = db.cursor(dictionary=True)

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
                    cur = db.cursor()
                    cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))
                    db.commit()

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
                        return redirect(url_for('admin_dashboard'))  # FIXED: no slash
                    elif user['user_type'] == 'expert':
                        print("🚀 Redirecting to EXPERT DASHBOARD")
                        # You need to create this route if it doesn't exist
                        return redirect(url_for('expert_dashboard'))  # FIXED: no slash
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
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

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
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get user stats
            cur.execute("""
                SELECT 
                    COUNT(*) as total_diagnoses,
                    COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) as today_diagnoses,
                    AVG(confidence) as avg_confidence
                FROM diagnosis_history 
                WHERE user_id = %s
            """, (user_id,))
            stats = cur.fetchone()

            if not stats:
                stats = {'total_diagnoses': 0, 'today_diagnoses': 0, 'avg_confidence': 0}
            else:
                stats['avg_confidence'] = round(stats['avg_confidence'] or 0, 1)

            # Get saved count - Note: This table might need updating too
            # If you're not using saved_diagnoses anymore, you can remove this
            try:
                cur.execute("""
                    SELECT COUNT(*) as saved_count
                    FROM saved_diagnoses 
                    WHERE user_id = %s
                """, (user_id,))
                saved_result = cur.fetchone()
                saved_count = saved_result['saved_count'] if saved_result else 0
            except:
                # If saved_diagnoses table doesn't exist, just set to 0
                saved_count = 0
                print("Note: saved_diagnoses table doesn't exist")

            # --- UPDATED: Get recent diagnoses WITHOUT image_path ---
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
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route("/profile")
    @login_required
    def profile():
        """User profile page"""
        user_id = session['user_id']
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get user data
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

            # Get stats
            cur.execute("""
                SELECT 
                    COUNT(*) as total_diagnosis,
                    (SELECT COUNT(*) FROM saved_diagnoses WHERE user_id = %s) as saved_items,
                    DATEDIFF(NOW(), MIN(created_at)) as days_active
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
                    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1) as percentage
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
                    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1) as percentage
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
            profile_completion = int((completed_count / len(completion_items)) * 100)

            return render_template("profile.html",
                                   user=user,
                                   stats=stats,
                                   recent_activity=recent_activity,
                                   crop_expertise=crop_expertise,
                                   common_diseases=common_diseases,
                                   completion_items=completion_items,
                                   profile_completion=profile_completion,
                                   badges=[])  # Add badges logic if you have it

        except Exception as e:
            print(f"Profile error: {e}")
            flash('Error loading profile', 'danger')
            return redirect(url_for('dashboard'))
        finally:
            if cur:
                cur.close()
            if db:
                db.close()

    @app.route("/api/profile/update-bio", methods=["POST"])
    @login_required
    def update_bio():
        """Update user bio"""
        user_id = session['user_id']
        db = None
        cur = None

        try:
            data = request.get_json()
            bio = data.get('bio', '').strip()

            # Validate length
            if len(bio) > 500:
                return jsonify({'success': False, 'error': 'Bio must be 500 characters or less'}), 400

            db = get_db()
            cur = db.cursor()

            cur.execute("""
                UPDATE users 
                SET bio = %s, updated_at = NOW() 
                WHERE id = %s
            """, (bio, user_id))

            db.commit()

            return jsonify({
                'success': True,
                'message': 'Bio updated successfully',
                'bio': bio
            })

        except Exception as e:
            print(f"Update bio error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route("/api/profile/upload-image", methods=["POST"])
    @login_required
    def upload_profile_image():
        """Upload profile image"""
        user_id = session['user_id']
        db = None
        cur = None

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
            db = get_db()
            cur = db.cursor(dictionary=True)
            cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            cur.close()

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
            cur = db.cursor()
            cur.execute("""
                UPDATE users 
                SET profile_image = %s, updated_at = NOW() 
                WHERE id = %s
            """, (filename, user_id))
            db.commit()

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
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route("/change-password", methods=["POST"])
    @login_required
    def change_password():
        """Change user password"""
        user_id = session['user_id']
        db = None
        cur = None

        try:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if new_password != confirm_password:
                return jsonify({'success': False, 'message': 'Passwords do not match!'})

            valid, message = validate_password(new_password)
            if not valid:
                return jsonify({'success': False, 'message': message})

            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get current password hash
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

            if not user or not check_password(current_password, user['password_hash']):
                return jsonify({'success': False, 'message': 'Current password is incorrect!'})

            # Update password
            new_hash = hash_password(new_password)
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                        (new_hash, user_id))

            db.commit()

            return jsonify({'success': True, 'message': 'Password changed successfully!'})

        except Exception as e:
            print(f"Password change error: {e}")
            return jsonify({'success': False, 'message': 'Failed to change password!'})
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    # ========== HISTORY ROUTES ==========

    @app.route("/history")
    @login_required
    def history():
        """View diagnosis history with pagination and filters"""
        user_id = session['user_id']
        db = None
        cur = None

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

            db = get_db()
            cur = db.cursor(dictionary=True)

            # --- BUILD MAIN QUERY WITH FILTERS ---
            query = """
                SELECT dh.*, u.username,
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
                        WHERE diagnosis_id = dh.id AND user_id = %s
                    )
                """
                count_params.append(user_id)

            cur.execute(count_query, count_params)
            total = cur.fetchone()['total']

            # --- STATS (also filtered) ---
            # Total diagnoses
            cur.execute(count_query, count_params)
            total_diagnoses = cur.fetchone()['total']

            # Monthly diagnoses
            monthly_query = """
                SELECT COUNT(*) as monthly_diagnoses
                FROM diagnosis_history dh
                WHERE dh.user_id = %s
                AND YEAR(dh.created_at) = YEAR(CURDATE())
                AND MONTH(dh.created_at) = MONTH(CURDATE())
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
            monthly_diagnoses = cur.fetchone()['monthly_diagnoses']

            # Average confidence
            cur.execute("""
                SELECT COALESCE(AVG(confidence), 0) as avg_confidence
                FROM diagnosis_history dh
                WHERE dh.user_id = %s
            """, (user_id,))
            avg_confidence = round(cur.fetchone()['avg_confidence'], 1)

            # Saved count
            cur.execute("""
                SELECT COUNT(*) as saved_count
                FROM saved_diagnoses
                WHERE user_id = %s
            """, (user_id,))
            saved_count = cur.fetchone()['saved_count']

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
            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
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
            flash('Error loading history', 'danger')
            return redirect(url_for('dashboard'))
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

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

            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get diagnosis details
            cur.execute("""
                SELECT * FROM diagnosis_history 
                WHERE id = %s AND user_id = %s
            """, (diagnosis_id, user_id))

            diagnosis = cur.fetchone()

            if not diagnosis:
                cur.close()
                db.close()
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

            cur.close()
            db.close()

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

            # ===== DEBUG: Print the result =====
            print("=" * 50)
            print("RESULT DATA PASSED TO TEMPLATE:")
            print(f"ID: {result['id']}")
            print(f"Disease: {result['disease']}")
            print(f"Crop: {result['crop']}")

            print(f"Symptoms: {result['symptoms']}")
            print(f"Recommendations: {result['recommendations']}")
            print(f"Created at: {result['created_at']}")
            print("=" * 50)

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
        db = None
        cur = None

        try:
            action = request.json.get('action', 'save')
            db = get_db()
            cur = db.cursor()

            if action == 'save':
                notes = request.json.get('notes', '')
                cur.execute("""
                    INSERT IGNORE INTO saved_diagnoses (user_id, diagnosis_id, notes)
                    VALUES (%s, %s, %s)
                """, (user_id, diagnosis_id, notes))
                message = 'Diagnosis saved!'
            else:
                cur.execute("""
                    DELETE FROM saved_diagnoses 
                    WHERE user_id = %s AND diagnosis_id = %s
                """, (user_id, diagnosis_id))
                message = 'Diagnosis removed from saved!'

            db.commit()

            return jsonify({'success': True, 'message': message})

        except Exception as e:
            print(f"Save diagnosis error: {e}")
            return jsonify({'success': False, 'message': 'Operation failed!'})
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route("/saved")
    @login_required
    def saved_diagnoses():
        """View saved diagnoses"""
        user_id = session['user_id']
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get saved diagnoses - join with diagnosis_history to get the image
            cur.execute("""
                SELECT sd.*, dh.image
                FROM saved_diagnoses sd
                JOIN diagnosis_history dh ON sd.id = dh.id
                WHERE sd.user_id = %s
                ORDER BY sd.created_at DESC
            """, (user_id,))
            saved_diagnoses = cur.fetchall()

            # --- CALCULATE STATS ---
            total_saved = len(saved_diagnoses)

            # Unique diseases count
            unique_diseases = len(set([d['disease'] for d in saved_diagnoses if d.get('disease')]))

            # Unique crops count
            unique_crops = len(set([d['crop'] for d in saved_diagnoses if d.get('crop')]))

            # Average confidence
            if saved_diagnoses:
                avg_confidence = sum([d['confidence'] for d in saved_diagnoses if d.get('confidence')]) / len(
                    saved_diagnoses)
                avg_confidence = round(avg_confidence, 1)
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
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route("/api/diagnosis/<int:diagnosis_id>", methods=["DELETE"])
    @login_required
    def delete_diagnosis(diagnosis_id):
        """Delete a diagnosis"""
        user_id = session['user_id']

        try:
            db = get_db()
            cur = db.cursor()

            # Delete the diagnosis
            cur.execute("""
                DELETE FROM diagnosis_history 
                WHERE id = %s AND user_id = %s
            """, (diagnosis_id, user_id))

            db.commit()
            cur.close()
            db.close()

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
            db = get_db()
            cur = db.cursor()

            # Delete all diagnoses for this user
            cur.execute("""
                DELETE FROM diagnosis_history
                WHERE user_id = %s
            """, (user_id,))

            deleted_count = cur.rowcount
            db.commit()
            cur.close()
            db.close()

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
            db = get_db()
            cursor = db.cursor(dictionary=True)

            # Check if already saved (using diagnosis_id as the ID)
            cursor.execute("""
                SELECT id FROM saved_diagnoses 
                WHERE user_id = %s AND id = %s
            """, (user_id, diagnosis_id))

            existing = cursor.fetchone()

            if existing:
                # Remove from saved
                cursor.execute("""
                    DELETE FROM saved_diagnoses 
                    WHERE user_id = %s AND id = %s
                """, (user_id, diagnosis_id))
                saved = False
                message = "Diagnosis removed from saved"
            else:
                # Get diagnosis details from history
                cursor.execute("""
                    SELECT * FROM diagnosis_history WHERE id = %s
                """, (diagnosis_id,))
                diagnosis = cursor.fetchone()

                if not diagnosis:
                    return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

                # Save to saved_diagnoses - WITHOUT image_path
                cursor.execute("""
                    INSERT INTO saved_diagnoses 
                    (id, user_id, crop, disease, confidence, 
                     symptoms, recommendations, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    diagnosis['id'],
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

            db.commit()
            cursor.close()
            db.close()

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

            db = get_db()
            cursor = db.cursor()

            placeholders = ','.join(['%s'] * len(ids))
            cursor.execute(f"""
                SELECT id FROM saved_diagnoses 
                WHERE user_id = %s AND id IN ({placeholders})
            """, [user_id] + ids)

            saved = [row[0] for row in cursor.fetchall()]
            cursor.close()
            db.close()

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
                db = get_db()
                cur = db.cursor(dictionary=True)

                # Check if table exists first
                cur.execute("SHOW TABLES LIKE 'feedback'")
                if cur.fetchone():
                    cur.execute("""
                        SELECT * FROM feedback 
                        WHERE user_id = %s 
                        ORDER BY created_at DESC 
                        LIMIT 10
                    """, (user_id,))
                    user_feedback = cur.fetchall()
                cur.close()
                db.close()

        except Exception as e:
            print(f"Error loading user feedback: {e}")

        return render_template('feedback.html', user_feedback=user_feedback)

    @app.route('/feedback')
    def feedback_page():
        """Display feedback form and user's previous feedback"""
        user_feedback = []

        # If user is logged in, get their previous feedback
        if session.get('user_id'):
            db = get_db()
            cur = db.cursor(dictionary=True)

            cur.execute("""
                SELECT * FROM feedback 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT 10
            """, (session['user_id'],))

            user_feedback = cur.fetchall()
            cur.close()
            db.close()

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

            # Get database connection
            db = get_db()
            cur = db.cursor()  # Make sure this is correct for your DB connector

            # Insert into database
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

            db.commit()
            cur.close()
            db.close()

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
            db = get_db()
            cur = db.cursor()

            # Check if table exists
            cur.execute("SHOW TABLES LIKE 'feedback'")
            if not cur.fetchone():
                return "❌ feedback table does not exist!"

            # Show table structure
            cur.execute("DESCRIBE feedback")
            columns = cur.fetchall()

            result = "<h3>Feedback Table Structure:</h3><ul>"
            for col in columns:
                result += f"<li>{col[0]} - {col[1]}</li>"
            result += "</ul>"

            cur.close()
            db.close()

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
        db = None
        cur = None

        try:
            # Verify diagnosis belongs to user
            db = get_db()
            cur = db.cursor(dictionary=True)
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
                    ON DUPLICATE KEY UPDATE
                    rating = VALUES(rating),
                    accuracy_rating = VALUES(accuracy_rating),
                    feedback_text = VALUES(feedback_text),
                    suggestions = VALUES(suggestions),
                    created_at = NOW()
                """, (user_id, diagnosis_id, rating, accuracy, feedback_text, suggestions))

                db.commit()

                flash('Thank you for your feedback!', 'success')
                return redirect(url_for('view_diagnosis', diagnosis_id=diagnosis_id))

            # GET request - show feedback form
            cur.execute("SELECT * FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
            diagnosis = cur.fetchone()

            return render_template("feedback_form.html", diagnosis=diagnosis)

        except Exception as e:
            print(f"Feedback error: {e}")
            flash('Failed to submit feedback.', 'danger')
            return redirect(url_for('view_diagnosis', diagnosis_id=diagnosis_id))
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route("/api/feedback/stats")
    @login_required
    def feedback_stats():
        """Get feedback statistics for admin"""
        if session.get('user_type') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403

        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

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
                JOIN users u ON f.user_id = u.id
                JOIN diagnosis_history dh ON f.diagnosis_id = dh.id
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
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

        # ========== ADMIN DASHBOARD ==========

    @app.route("/admin/dashboard")
    @admin_required
    def admin_dashboard():
        """Admin dashboard with comprehensive analytics"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get user statistics
            cur.execute("""
                SELECT 
                    COUNT(*) as total_users,
                    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users,
                    SUM(CASE WHEN is_active = 0 OR is_active IS NULL THEN 1 ELSE 0 END) as inactive_users,
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
                WHERE DATE(created_at) = CURDATE()
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
                WHERE MONTH(created_at) = MONTH(CURDATE()) 
                AND YEAR(created_at) = YEAR(CURDATE())
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

            # Convert Decimal values in top_diseases
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
                SELECT COUNT(*) as table_exists 
                FROM information_schema.tables 
                WHERE table_schema = DATABASE() 
                AND table_name = 'feedback'
            """)
            feedback_table_exists = cur.fetchone()['table_exists'] > 0

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
            cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 0")
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
        finally:
            if cur: cur.close()
            if db: db.close()

    # ========== ADMIN USER MANAGEMENT ==========
    @app.route("/admin/users")
    @admin_required
    def admin_users():
        """Admin - User management with CRUD operations"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

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

            if user_type:
                query += " AND user_type = %s"
                count_query += " AND user_type = %s"
                params.append(user_type)

            if status == 'active':
                query += " AND is_active = 1"
                count_query += " AND is_active = 1"
            elif status == 'inactive':
                query += " AND is_active = 0"
                count_query += " AND is_active = 0"

            if search:
                query += " AND (username LIKE %s OR email LIKE %s OR full_name LIKE %s)"
                count_query += " AND (username LIKE %s OR email LIKE %s OR full_name LIKE %s)"
                search_param = f"%{search}%"
                params.extend([search_param, search_param, search_param])

            # Get total count
            cur.execute(count_query, params)
            total_users = cur.fetchone()['total'] or 0
            total_pages = (total_users + per_page - 1) // per_page

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
                    SUM(CASE WHEN DATE(last_login) = CURDATE() THEN 1 ELSE 0 END) as active_today,
                    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users,
                    SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive_users
                FROM users
            """)
            stats = cur.fetchone()

            # Get pending counts
            cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
            pending_feedback = cur.fetchone()['count'] or 0

            # Get pending diseases count (if you have a disease_info table with status)
            try:
                cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE status = 'pending'")
                pending_diseases = cur.fetchone()['count'] or 0
            except:
                pending_diseases = 0

            # Get pending reviews count
            cur.execute("SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending'")
            pending_reviews = cur.fetchone()['count'] or 0

            # Create sidebar stats with ALL needed fields
            sidebar_stats = {
                'pending_users': stats['inactive_users'] if stats else 0,
                'pending_feedback': pending_feedback,
                'pending_diseases': pending_diseases,
                'pending_reviews': pending_reviews  # ← ADD THIS
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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/user/create", methods=["POST"])
    @admin_required
    def admin_create_user():
        """Admin - Create new user"""
        db = None
        cur = None

        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            user_type = request.form.get('user_type')
            phone = request.form.get('phone')
            location = request.form.get('location')

            db = get_db()
            cur = db.cursor(dictionary=True)

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
                VALUES (%s, %s, %s, %s, %s, %s, %s, 1, NOW())
            """, (username, email, password_hash, full_name, user_type, phone, location))

            user_id = cur.lastrowid

            # Create default settings
            try:
                cur.execute("""
                    INSERT INTO user_settings (user_id) VALUES (%s)
                """, (user_id,))
            except:
                pass  # Settings table might not exist

            db.commit()

            # Log activity (if table exists)
            try:
                cur.execute("""
                    INSERT INTO activity_logs (user_id, action, entity_type, entity_id, ip_address, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (session['user_id'], f"Created user: {username}", 'user', user_id, request.remote_addr))
                db.commit()
            except:
                pass

            flash(f'User {username} created successfully!', 'success')

        except Exception as e:
            print(f"Create user error: {e}")
            if db: db.rollback()
            flash('Error creating user', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('admin_users'))

    @app.route("/admin/user/<int:user_id>/update", methods=["POST"])
    @admin_required
    def admin_update_user(user_id):
        """Admin - Update user details"""
        db = None
        cur = None

        try:
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            location = request.form.get('location')
            user_type = request.form.get('user_type')

            db = get_db()
            cur = db.cursor()

            cur.execute("""
                UPDATE users 
                SET full_name = %s, phone_number = %s, location = %s, 
                    user_type = %s, updated_at = NOW()
                WHERE id = %s
            """, (full_name, phone, location, user_type, user_id))

            db.commit()

            flash('User updated successfully!', 'success')

        except Exception as e:
            print(f"Update user error: {e}")
            flash('Error updating user', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('admin_users'))

    @app.route("/admin/user/<int:user_id>/toggle-status", methods=["POST"])
    @admin_required
    def admin_toggle_user_status(user_id):
        """Admin - Activate/Deactivate user"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get current status
            cur.execute("SELECT username, is_active FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404

            # Toggle status
            new_status = not user['is_active']
            cur.execute("UPDATE users SET is_active = %s, updated_at = NOW() WHERE id = %s",
                        (new_status, user_id))
            db.commit()

            return jsonify({'success': True, 'is_active': new_status})

        except Exception as e:
            print(f"Toggle user status error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
    @admin_required
    def admin_delete_user(user_id):
        """Admin - Delete user"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get username
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404

            # Don't allow deleting own account
            if user_id == session['user_id']:
                return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

            # Delete user settings first
            try:
                cur.execute("DELETE FROM user_settings WHERE user_id = %s", (user_id,))
            except:
                pass

            # Delete user
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            db.commit()

            return jsonify({'success': True})

        except Exception as e:
            print(f"Delete user error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/api/admin/user/<int:user_id>")
    @admin_required
    def admin_get_user(user_id):
        """API - Get user details"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/users/export")
    @admin_required
    def admin_export_users():
        """Admin - Export users to CSV"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

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
        finally:
            if cur: cur.close()
            if db: db.close()

            # ========== ADMIN FEEDBACK MANAGEMENT ==========

    @app.route('/admin/feedback')
    @admin_required
    def admin_feedback():
        """Admin view to see all feedback"""
        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get filter parameters
            status = request.args.get('status', '')
            category = request.args.get('category', '')
            search = request.args.get('search', '')

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
                query += " AND (f.subject LIKE %s OR f.message LIKE %s OR f.name LIKE %s OR f.email LIKE %s)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term, search_term])

            query += " ORDER BY f.created_at DESC"

            cur.execute(query, params)
            feedback_list = cur.fetchall()

            # Get unique categories for filter dropdown
            cur.execute("SELECT DISTINCT feedback_type FROM feedback")
            category_rows = cur.fetchall()
            categories = [row['feedback_type'] for row in category_rows if row['feedback_type']]

            # Get sidebar stats
            cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 0")
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
                'pending_reviews': pending_reviews  # ← ADD THIS
            }

            cur.close()
            db.close()

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

        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # REMOVED the diagnosis_history JOIN since the column doesn't exist
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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/feedback/<int:feedback_id>/reply", methods=["POST"])
    @login_required
    def admin_reply_feedback(feedback_id):
        """Admin - Reply to feedback - DOES NOT change status"""
        # Check if user is admin
        if session.get('user_type') != 'admin':
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 401

        db = None
        cur = None

        try:
            data = request.get_json()
            reply = data.get('reply', '').strip()

            if not reply:
                return jsonify({'success': False, 'error': 'Reply cannot be empty'}), 400

            db = get_db()
            cur = db.cursor()

            # Only update admin_response - DO NOT change status
            cur.execute("""
                UPDATE feedback 
                SET admin_response = %s
                WHERE id = %s
            """, (reply, feedback_id))

            db.commit()

            return jsonify({'success': True, 'message': 'Reply saved successfully'})

        except Exception as e:
            print(f"Reply feedback error: {e}")
            if db:
                db.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/feedback/<int:feedback_id>/status", methods=["POST"])
    @login_required
    def admin_update_feedback_status(feedback_id):
        """Admin - Manually update feedback status"""
        # Check if user is admin
        if session.get('user_type') != 'admin':
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 401

        db = None
        cur = None

        try:
            data = request.get_json()
            status = data.get('status')

            if status not in ['pending', 'reviewed', 'resolved']:
                return jsonify({'success': False, 'error': 'Invalid status'}), 400

            db = get_db()
            cur = db.cursor()

            # Update only the status
            cur.execute("""
                UPDATE feedback 
                SET status = %s
                WHERE id = %s
            """, (status, feedback_id))

            db.commit()

            return jsonify({'success': True})

        except Exception as e:
            print(f"Update feedback status error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    # ========== SETTINGS ROUTES ==========

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        """User settings page with profile management"""
        user_id = session.get('user_id')

        if not user_id:
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Get user information
        cursor.execute("""
            SELECT id, username, email, full_name, phone_number, 
                   location, profile_image, user_type, is_active, 
                   created_at, last_login, bio, language
            FROM users WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            return redirect(url_for('login'))

        # Get user settings
        cursor.execute("SELECT * FROM user_settings WHERE user_id = %s", (user_id,))
        settings_data = cursor.fetchone()

        # If no settings exist, create default settings
        if not settings_data:
            cursor.execute("""
                INSERT INTO user_settings (user_id) VALUES (%s)
            """, (user_id,))
            db.commit()

            cursor.execute("SELECT * FROM user_settings WHERE user_id = %s", (user_id,))
            settings_data = cursor.fetchone()

        # Get account statistics
        cursor.execute("""
            SELECT 
                created_at,
                last_login,
                (SELECT COUNT(*) FROM diagnosis_history WHERE user_id = %s) as total_diagnosis,
                0 as saved_items
            FROM users WHERE id = %s
        """, (user_id, user_id))
        stats = cursor.fetchone()

        cursor.close()
        db.close()

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

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Update email
        cursor.execute("UPDATE users SET email = %s WHERE id = %s", (email, user_id))

        # Handle password change if provided
        if current_password and new_password and confirm_password:
            # Verify current password
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()

            from auth import check_password_hash
            if user and check_password_hash(user['password_hash'], current_password):
                if new_password == confirm_password:
                    from auth import generate_password_hash
                    hashed_password = generate_password_hash(new_password)
                    cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, user_id))
                    flash('Password updated successfully!', 'success')
                else:
                    flash('New passwords do not match!', 'danger')
                    db.close()
                    return redirect(url_for('settings') + '#account')
            else:
                flash('Current password is incorrect!', 'danger')
                db.close()
                return redirect(url_for('settings') + '#account')

        db.commit()
        cursor.close()
        db.close()

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

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Get current user data to check existing image
        cursor.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
        current_user = cursor.fetchone()

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
                    cursor.close()
                    db.close()
                    return redirect(url_for('settings') + '#profile')

        # Update user profile
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

        cursor.execute(update_query, params)
        db.commit()

        cursor.close()
        db.close()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('settings') + '#profile')

    def handle_notifications_form(user_id, form_data):
        """Handle notifications form submission"""
        db = get_db()
        cursor = db.cursor()

        # Get checkbox values (checkboxes return 'on' when checked, None when not checked)
        email_notifications = 1 if form_data.get('email_notifications') == 'on' else 0
        email_updates = 1 if form_data.get('email_updates') == 'on' else 0
        email_newsletter = 1 if form_data.get('email_newsletter') == 'on' else 0
        email_promotions = 1 if form_data.get('email_promotions') == 'on' else 0
        app_notifications = 1 if form_data.get('app_notifications') == 'on' else 0
        app_security = 1 if form_data.get('app_security') == 'on' else 0
        app_reminders = 1 if form_data.get('app_reminders') == 'on' else 0
        frequency = form_data.get('frequency', 'realtime')

        cursor.execute("""
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

        db.commit()
        cursor.close()
        db.close()

        flash('Notification settings updated!', 'success')
        return redirect(url_for('settings') + '#notifications')

    def handle_privacy_form(user_id, form_data):
        """Handle privacy form submission"""
        db = get_db()
        cursor = db.cursor()

        profile_public = 1 if form_data.get('profile_public') == 'on' else 0
        show_diagnosis = 1 if form_data.get('show_diagnosis') == 'on' else 0
        data_collection = 1 if form_data.get('data_collection') == 'on' else 0

        cursor.execute("""
            UPDATE user_settings 
            SET profile_public = %s,
                show_diagnosis = %s,
                data_collection = %s
            WHERE user_id = %s
        """, (profile_public, show_diagnosis, data_collection, user_id))

        db.commit()
        cursor.close()
        db.close()

        flash('Privacy settings updated!', 'success')
        return redirect(url_for('settings') + '#privacy')

    def handle_preferences_form(user_id, form_data):
        """Handle preferences form submission"""
        db = get_db()
        cursor = db.cursor()

        theme = form_data.get('theme', 'light')
        density = form_data.get('density', 'comfortable')
        auto_save = 1 if form_data.get('auto_save') == 'on' else 0
        show_tips = 1 if form_data.get('show_tips') == 'on' else 0
        detailed_results = 1 if form_data.get('detailed_results') == 'on' else 0
        quick_analysis = 1 if form_data.get('quick_analysis') == 'on' else 0
        default_crop = form_data.get('default_crop', '')
        measurement_unit = form_data.get('measurement_unit', 'metric')

        cursor.execute("""
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

        db.commit()
        cursor.close()
        db.close()

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
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get period filter with safe default
            period = request.args.get('period', '30')
            days = int(period) if period and period.isdigit() else 30
            start_date = datetime.now() - timedelta(days=days)

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

            # ===== DAILY NEW USERS (NOT cumulative) =====
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

            # ===== DAILY DIAGNOSES (NOT cumulative) =====
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
            cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 0")
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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/settings")
    @admin_required
    def admin_settings():
        """Admin settings page - separate from farmer settings"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

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
            cur.execute("""
                SELECT * FROM user_settings 
                WHERE user_id = %s
            """, (session['user_id'],))
            user_settings = cur.fetchone()

            # If no settings exist, create default
            if not user_settings:
                cur.execute("""
                    INSERT INTO user_settings (user_id) VALUES (%s)
                """, (session['user_id'],))
                db.commit()

                cur.execute("""
                    SELECT * FROM user_settings 
                    WHERE user_id = %s
                """, (session['user_id'],))
                user_settings = cur.fetchone()

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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/admin/settings/update", methods=["POST"])
    @admin_required
    def admin_update_settings():
        """Update admin profile settings"""
        db = None
        cur = None

        try:
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            location = request.form.get('location')
            bio = request.form.get('bio')

            # Get notification preferences
            email_notifications = 1 if request.form.get('email_notifications') == 'on' else 0
            app_notifications = 1 if request.form.get('app_notifications') == 'on' else 0

            db = get_db()
            cur = db.cursor()

            # Update users table
            cur.execute("""
                UPDATE users 
                SET full_name = %s, email = %s, phone_number = %s, 
                    location = %s, bio = %s, updated_at = NOW()
                WHERE id = %s
            """, (full_name, email, phone, location, bio, session['user_id']))

            # Update user_settings table
            cur.execute("""
                UPDATE user_settings 
                SET email_notifications = %s, app_notifications = %s
                WHERE user_id = %s
            """, (email_notifications, app_notifications, session['user_id']))

            db.commit()

            # Update session
            session['full_name'] = full_name
            session['email'] = email

            flash('Admin profile updated successfully!', 'success')

        except Exception as e:
            print(f"Admin update settings error: {e}")
            if db:
                db.rollback()
            flash('Error updating profile', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('admin_settings'))

    @app.route("/admin/history")
    @admin_required
    def admin_history():
        """Admin view of all diagnosis history with expert reviews"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get filter parameters
            expert_review_status = request.args.get('expert_review_status', '')
            image_processed = request.args.get('image_processed', '')
            final_confidence_level = request.args.get('final_confidence_level', '')
            crop = request.args.get('crop', '')
            farmer = request.args.get('farmer', '')

            page = request.args.get('page', 1, type=int)
            per_page = 20
            offset = (page - 1) * per_page

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
                params.append(int(image_processed))
                count_params.append(int(image_processed))

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
                query += " AND u.username LIKE %s"
                count_query += " AND u.username LIKE %s"
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
            crop_rows = cur.fetchall()
            crops = [row['crop'] for row in crop_rows] if crop_rows else []

            # Get sidebar stats - UPDATED to use expert_review_status
            cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 0")
            pending_users = cur.fetchone()['count'] or 0

            cur.execute("SELECT COUNT(*) as count FROM feedback WHERE status = 'pending'")
            pending_feedback = cur.fetchone()['count'] or 0

            # THIS IS THE KEY CHANGE - Use expert_review_status instead of review_status
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
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    # ========== EXPERT DASHBOARD ==========
    @app.route("/expert/dashboard")
    @expert_required
    def expert_dashboard():
        """Expert dashboard - simplified version"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            expert_id = session['user_id']

            # Get expert basic info from users table (only existing columns)
            cur.execute("""
                SELECT username, full_name, email, profile_image, created_at
                FROM users WHERE id = %s
            """, (expert_id,))
            expert = cur.fetchone()

            # Get statistics from diagnosis_history
            # Total diagnoses in system that need review
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
        finally:
            if cur: cur.close()
            if db: db.close()

    # ========== EXPERT DISEASE MANAGEMENT ==========
    @app.route("/expert/diseases")
    @expert_required
    def expert_diseases():
        """Expert - Manage disease library"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Fix: Use correct column names from your disease_info table
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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/expert/diseases/add", methods=["POST"])
    @expert_required
    def expert_add_disease():
        """Expert - Add new disease"""
        db = None
        cur = None

        try:
            # Get form data matching your table columns
            crop = request.form.get('crop')
            disease_code = request.form.get('disease_code')
            disease_name = request.form.get('disease_name')
            cause = request.form.get('cause')
            symptoms = request.form.get('symptoms')
            organic_treatment = request.form.get('organic_treatment')
            chemical_treatment = request.form.get('chemical_treatment')
            prevention = request.form.get('prevention')
            manual_treatment = request.form.get('manual_treatment')

            db = get_db()
            cur = db.cursor()

            cur.execute("""
                INSERT INTO disease_info (
                    crop, disease_code, disease_name, cause, symptoms,
                    organic_treatment, chemical_treatment, prevention, 
                    manual_treatment, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (crop, disease_code, disease_name, cause, symptoms,
                  organic_treatment, chemical_treatment, prevention, manual_treatment))

            db.commit()

            flash('Disease added successfully!', 'success')

        except Exception as e:
            print(f"Add disease error: {e}")
            flash('Error adding disease', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_diseases'))

    @app.route("/expert/diseases/<int:disease_id>/edit", methods=["POST"])
    @expert_required
    def expert_edit_disease(disease_id):
        """Expert - Edit disease"""
        db = None
        cur = None

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

            db = get_db()
            cur = db.cursor()

            cur.execute("""
                UPDATE disease_info 
                SET crop = %s, disease_code = %s, disease_name = %s,
                    cause = %s, symptoms = %s, organic_treatment = %s,
                    chemical_treatment = %s, prevention = %s,
                    manual_treatment = %s, created_at = NOW()
                WHERE id = %s
            """, (crop, disease_code, disease_name, cause, symptoms,
                  organic_treatment, chemical_treatment, prevention,
                  manual_treatment, disease_id))

            db.commit()

            flash('Disease updated successfully!', 'success')

        except Exception as e:
            print(f"Edit disease error: {e}")
            flash('Error updating disease', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_diseases'))

    @app.route("/expert/diseases/<int:disease_id>/delete", methods=["POST"])
    @login_required
    @expert_required
    def expert_delete_disease(disease_id):
        """Expert - Delete disease"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor()

            cur.execute("DELETE FROM disease_info WHERE id = %s", (disease_id,))
            db.commit()

            flash('Disease deleted successfully!', 'success')

        except Exception as e:
            print(f"Delete disease error: {e}")
            flash('Error deleting disease', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_diseases'))

    # ========== EXPERT DETECTION REVIEW ==========
    @app.route("/expert/views")
    @expert_required
    def expert_pending_reviews():
        """Expert - View pending diagnoses from diagnosis_history"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            # FIXED: Use expert_review_status = 'pending' instead of training_used = 0
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
            total_pages = (total + per_page - 1) // per_page

            # Get all diseases for reference
            cur.execute("SELECT id, disease_name, crop FROM disease_info ORDER BY crop, disease_name")
            diseases = cur.fetchall()

            return render_template("expert/pending_reviews.html",
                                   diagnoses=diagnoses,
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   diseases=diseases,
                                   pending_count=total)  # Use total instead of get_pending_count()

        except Exception as e:
            print(f"Pending reviews error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading pending reviews', 'danger')
            return redirect(url_for('expert_dashboard'))
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/expert/review/<int:diagnosis_id>", methods=["POST"])
    @expert_required
    def expert_review_detection(diagnosis_id):
        """Expert - Review a disease detection"""
        db = None
        cur = None

        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400

            print(f"Received review data: {data}")

            action = data.get('action')
            expert_notes = data.get('expert_notes', '')
            corrected_disease = data.get('corrected_disease_id')

            # Convert notes to JSON format (even if empty)
            import json
            if not expert_notes or expert_notes.strip() == '':
                expert_notes_json = json.dumps({"notes": "No notes provided"})
            else:
                expert_notes_json = json.dumps({"notes": expert_notes})

            db = get_db()
            cur = db.cursor()

            # First, check if the diagnosis exists
            cur.execute("SELECT id FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
            if not cur.fetchone():
                return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

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
                cur.execute("SELECT disease_name FROM disease_info WHERE id = %s", (corrected_disease,))
                disease_result = cur.fetchone()

                if not disease_result:
                    return jsonify({'success': False, 'error': 'Selected disease not found'}), 404

                correct_disease_name = disease_result[0]

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

            db.commit()
            print(f"Successfully updated diagnosis {diagnosis_id}")
            return jsonify({'success': True})

        except Exception as e:
            print(f"Review error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/expert/history")
    @expert_required
    def expert_history():
        """Expert - View review history"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            expert_id = session['user_id']  # You might want to track which expert reviewed
            page = int(request.args.get('page', 1))
            per_page = 10
            offset = (page - 1) * per_page

            # Get filter parameters
            farmer = request.args.get('farmer', '')
            disease = request.args.get('disease', '')
            status = request.args.get('status', '')
            date_from = request.args.get('date_from', '')
            date_to = request.args.get('date_to', '')

            # Base query
            query = """
                SELECT dh.*, u.username as farmer_name, u.full_name as farmer_full_name
                FROM diagnosis_history dh
                JOIN users u ON dh.user_id = u.id
                WHERE dh.training_used = 1
            """
            count_query = "SELECT COUNT(*) as total FROM diagnosis_history dh WHERE training_used = 1"
            params = []
            count_params = []

            # Apply filters
            if farmer:
                query += " AND (u.username LIKE %s OR u.full_name LIKE %s)"
                count_query += " AND (u.username LIKE %s OR u.full_name LIKE %s)"
                params.extend([f'%{farmer}%', f'%{farmer}%'])
                count_params.extend([f'%{farmer}%', f'%{farmer}%'])

            if disease:
                query += " AND dh.disease_detected LIKE %s"
                count_query += " AND dh.disease_detected LIKE %s"
                params.append(f'%{disease}%')
                count_params.append(f'%{disease}%')

            if status == 'approved':
                query += " AND dh.for_training = 1"
                count_query += " AND dh.for_training = 1"
            elif status == 'rejected':
                query += " AND dh.for_training = 0"
                count_query += " AND dh.for_training = 0"

            if date_from:
                query += " AND DATE(dh.created_at) >= %s"
                count_query += " AND DATE(dh.created_at) >= %s"
                params.append(date_from)
                count_params.append(date_from)

            if date_to:
                query += " AND DATE(dh.created_at) <= %s"
                count_query += " AND DATE(dh.created_at) <= %s"
                params.append(date_to)
                count_params.append(date_to)

            # Add order by and pagination
            query += " ORDER BY dh.created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, offset])

            # Execute main query
            cur.execute(query, params)
            reviews = cur.fetchall()

            # Get total count for pagination
            cur.execute(count_query, count_params)
            total = cur.fetchone()['total'] or 0
            total_pages = (total + per_page - 1) // per_page

            # Get statistics
            stats_query = """
                SELECT 
                    COUNT(*) as total_reviews,
                    SUM(CASE WHEN for_training = 1 THEN 1 ELSE 0 END) as approved_count,
                    SUM(CASE WHEN for_training = 0 THEN 1 ELSE 0 END) as rejected_count
                FROM diagnosis_history 
                WHERE training_used = 1
            """
            cur.execute(stats_query)
            stats = cur.fetchone()

            # Add pending count
            cur.execute("SELECT COUNT(*) as total FROM diagnosis_history WHERE training_used = 0")
            pending_result = cur.fetchone()
            stats['pending_count'] = pending_result['total'] or 0

            return render_template("expert/history.html",
                                   reviews=reviews,
                                   page=page,
                                   total_pages=total_pages,
                                   total_results=total,
                                   stats=stats,
                                   pending_count=get_pending_count())

        except Exception as e:
            print(f"Expert history error: {e}")
            import traceback
            traceback.print_exc()
            flash('Error loading history', 'danger')
            return redirect(url_for('expert_dashboard'))
        finally:
            if cur: cur.close()
            if db: db.close()

    # ========== EXPERT SETTINGS ROUTES ==========

    @app.route("/expert/settings")
    @expert_required
    def expert_settings():
        """Expert settings page"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            expert_id = session['user_id']

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
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/expert/settings/update", methods=["POST"])
    @expert_required
    def expert_update_profile():
        """Update expert profile"""
        db = None
        cur = None

        try:
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            location = request.form.get('location')
            bio = request.form.get('bio')

            db = get_db()
            cur = db.cursor()

            cur.execute("""
                UPDATE users 
                SET full_name = %s, email = %s, phone_number = %s, 
                    location = %s, bio = %s, updated_at = NOW()
                WHERE id = %s
            """, (full_name, email, phone, location, bio, session['user_id']))

            db.commit()

            # Update session
            session['full_name'] = full_name
            session['email'] = email

            flash('Profile updated successfully!', 'success')

        except Exception as e:
            print(f"Update profile error: {e}")
            flash('Error updating profile', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_settings'))

    @app.route("/expert/change-password", methods=["POST"])
    @expert_required
    def expert_change_password():
        """Change expert password"""
        db = None
        cur = None

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

            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get current password hash
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
            user = cur.fetchone()

            if not user or not check_password(current_password, user['password_hash']):
                flash('Current password is incorrect!', 'danger')
                return redirect(url_for('expert_settings'))

            # Update password
            new_hash = hash_password(new_password)
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                        (new_hash, session['user_id']))

            db.commit()

            flash('Password changed successfully!', 'success')

        except Exception as e:
            print(f"Password change error: {e}")
            flash('Failed to change password!', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_settings'))

    @app.route("/expert/profile/upload-image", methods=["POST"])
    @expert_required
    def expert_upload_image():
        """Upload profile image for expert"""
        user_id = session['user_id']
        db = None
        cur = None

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
            db = get_db()
            cur = db.cursor(dictionary=True)
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
            cur.execute("""
                UPDATE users 
                SET profile_image = %s, updated_at = NOW() 
                WHERE id = %s
            """, (filename, user_id))
            db.commit()

            # Update session
            session['profile_image'] = filename

            flash('Profile image updated successfully!', 'success')

        except Exception as e:
            print(f"Upload image error: {e}")
            flash('Error uploading image', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_settings'))

    # ========== EXPERT QUESTION MANAGEMENT ROUTES ==========

    @app.route("/expert/questions")
    @expert_required
    def expert_questions():
        """Expert - View and manage all questions"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get filter parameters from request
            selected_crop = request.args.get('crop', '')
            selected_disease = request.args.get('disease', '')  # Changed from target
            selected_category = request.args.get('category', '')

            # Build the base query with your actual columns
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

            # Order by display_order (instead of priority)
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
                                   diseases=diseases,  # Changed from targets
                                   categories=categories,
                                   selected_crop=selected_crop,
                                   selected_disease=selected_disease,  # Changed from selected_target
                                   selected_category=selected_category,
                                   pending_count=pending_count,
                                   now=datetime.now())

        except Exception as e:
            print(f"Expert questions error: {e}")
            flash('Error loading questions: ' + str(e), 'danger')
            return redirect(url_for('expert_dashboard'))
        finally:
            if cur:
                cur.close()
            if db:
                db.close()

    @app.route("/expert/questions/add", methods=["GET", "POST"])
    @expert_required
    def expert_add_question():
        """Add a new question"""
        if request.method == "GET":
            # Show add form
            db = None
            cur = None
            try:
                db = get_db()
                cur = db.cursor(dictionary=True)

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
            finally:
                if cur: cur.close()
                if db: db.close()

        # POST - Process form
        db = None
        cur = None
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

            db = get_db()
            cur = db.cursor()

            cur.execute("""
                INSERT INTO questions 
                (crop, disease_code, question_text, question_category, display_order, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, (crop, disease_code, question_text, question_category, display_order))

            db.commit()

            flash('Question added successfully!', 'success')
            return redirect(url_for('expert_questions'))

        except Exception as e:
            print(f"Add question error: {e}")
            flash('Error adding question', 'danger')
            return redirect(url_for('expert_add_question'))
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route("/expert/questions/edit/<int:question_id>", methods=["GET", "POST"])
    @expert_required
    def expert_edit_question(question_id):
        """Edit an existing question"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            if request.method == "GET":
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

            # Update the question
            cur.execute("""
                UPDATE questions 
                SET crop = %s, 
                    disease_code = %s, 
                    question_text = %s, 
                    question_category = %s, 
                    display_order = %s
                WHERE id = %s
            """, (crop, disease_code, question_text, question_category, display_order, question_id))

            db.commit()

            flash('Question updated successfully!', 'success')
            return redirect(url_for('expert_questions'))

        except Exception as e:
            print(f"Edit question error: {e}")
            flash(f'Error updating question: {str(e)}', 'danger')
            return redirect(url_for('expert_edit_question', question_id=question_id))
        finally:
            if cur:
                cur.close()
            if db:
                db.close()

    @app.route("/expert/questions/delete/<int:question_id>", methods=["POST"])
    @expert_required
    def expert_delete_question(question_id):
        """Delete a question"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor()

            cur.execute("DELETE FROM questions WHERE id = %s", (question_id,))
            db.commit()

            flash('Question deleted successfully!', 'success')

        except Exception as e:
            print(f"Delete question error: {e}")
            flash('Error deleting question', 'danger')
        finally:
            if cur: cur.close()
            if db: db.close()

        return redirect(url_for('expert_questions'))

    @app.route('/api/diagnosis/<int:diagnosis_id>', methods=['GET'])
    @expert_required
    def api_get_diagnosis(diagnosis_id):
        """API endpoint to get diagnosis details for review modal"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get diagnosis details with farmer info
            cur.execute("""
                SELECT dh.*, u.username as farmer_name, u.full_name as farmer_full_name
                FROM diagnosis_history dh
                JOIN users u ON dh.user_id = u.id
                WHERE dh.id = %s
            """, (diagnosis_id,))

            diagnosis = cur.fetchone()

            if not diagnosis:
                return jsonify({'error': 'Diagnosis not found'}), 404

            # Convert confidence to float if it exists
            if diagnosis.get('confidence') is not None:
                diagnosis['confidence'] = float(diagnosis['confidence'])

            # Format the response with ALL needed fields
            response = {
                'id': diagnosis['id'],
                'user_id': diagnosis['user_id'],
                'farmer_name': diagnosis['farmer_full_name'] or diagnosis['farmer_name'],
                'crop': diagnosis['crop'],
                'disease_detected': diagnosis['disease_detected'],
                'symptoms': diagnosis['symptoms'],
                'recommendations': diagnosis['recommendations'],
                'confidence': diagnosis['confidence'],
                'final_confidence_level': diagnosis['final_confidence_level'],
                'expert_answers': diagnosis['expert_answers'],
                'expert_summary': diagnosis['expert_summary'],
                'image_processed': diagnosis['image_processed'],
                'for_training': diagnosis['for_training'],
                'training_used': diagnosis['training_used'],
                'created_at': diagnosis['created_at'].isoformat() if diagnosis['created_at'] else None
            }

            print(f"✅ API response for diagnosis {diagnosis_id}: confidence={response['confidence']}")
            return jsonify(response)

        except Exception as e:
            print(f"Error fetching diagnosis: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    @app.route('/expert/review/<int:diagnosis_id>', methods=['POST'])
    @expert_required
    def expert_submit_review(diagnosis_id):
        """Submit a review for a diagnosis"""
        db = None
        cur = None

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

            # Validate the action matches ENUM values
            valid_actions = ['accurate', 'needs correction', 'reject']
            if action not in valid_actions:
                print(f"Invalid action: '{action}'")
                return jsonify({
                    'success': False,
                    'error': f'Invalid action: {action}. Must be one of: {", ".join(valid_actions)}'
                }), 400

            # Set for_training flag based on action
            # Only accurate diagnoses should be used for training
            for_training = 1 if action == 'accurate' else 0

            # Prepare expert summary JSON to store in expert_summary field
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

            db = get_db()
            cur = db.cursor()

            # First, get the original diagnosis data in case we need it
            cur.execute("""
                SELECT user_id, crop, disease_detected, confidence, symptoms, 
                       recommendations, image 
                FROM diagnosis_history 
                WHERE id = %s
            """, (diagnosis_id,))
            original_diagnosis = cur.fetchone()

            if not original_diagnosis:
                return jsonify({'success': False, 'error': 'Diagnosis not found'}), 404

            # Update the diagnosis with review information - REMOVED review_status
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

            db.commit()
            rows_affected = cur.rowcount

            print(f"✅ Successfully updated diagnosis {diagnosis_id} (rows affected: {rows_affected})")

            # If this was a correction, create a new corrected record for training
            if action == 'needs correction' and corrected_disease_id and corrected_disease_name:
                try:
                    # Insert a new corrected record that can be used for training
                    cur.execute("""
                        INSERT INTO diagnosis_history 
                        (user_id, crop, disease_detected, confidence, symptoms, recommendations, 
                         expert_review_status, for_training, image, created_at,
                         expert_summary)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
                    """, (
                        original_diagnosis['user_id'],
                        original_diagnosis['crop'],
                        corrected_disease_name,  # Use the corrected disease name
                        100.00,  # High confidence for expert-corrected diagnosis
                        original_diagnosis['symptoms'],
                        original_diagnosis['recommendations'],
                        'accurate',  # Mark as accurate since it's expert-corrected
                        1,  # for_training = 1 (this should be used for training)
                        original_diagnosis['image'],
                        json.dumps({
                            'corrected_from': diagnosis_id,
                            'corrected_by': session.get('username'),
                            'correction_notes': expert_notes,
                            'corrected_at': datetime.now().isoformat()
                        })
                    ))
                    db.commit()
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
        finally:
            if cur:
                cur.close()
            if db:
                db.close()

    @app.route('/expert/disease-library')
    @login_required
    @expert_required
    def expert_disease_library():
        """Display disease library page for experts"""
        db = None
        cursor = None

        try:
            crop = request.args.get('crop', 'corn')
            if crop not in ['corn', 'rice']:
                crop = 'corn'
            page = request.args.get('page', 1, type=int)
            per_page = 12  # Number of diseases per page
            offset = (page - 1) * per_page

            db = get_db()
            cursor = db.cursor(dictionary=True)

            # Get total count for pagination
            cursor.execute("""
                SELECT COUNT(*) as total 
                FROM disease_info 
                WHERE crop = %s
            """, (crop,))
            total_result = cursor.fetchone()
            total = total_result['total'] if total_result else 0

            # Get diseases with pagination
            cursor.execute("""
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

            diseases = cursor.fetchall()

            # Get crop statistics for filter buttons
            cursor.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'corn'")
            corn_count_result = cursor.fetchone()
            corn_count = corn_count_result['count'] if corn_count_result else 0

            cursor.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'rice'")
            rice_count_result = cursor.fetchone()
            rice_count = rice_count_result['count'] if rice_count_result else 0

            crop_stats = {
                'corn_count': corn_count,
                'rice_count': rice_count
            }

            # Get sample images for each disease
            for disease in diseases:
                sample_cursor = None
                try:
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
                        LIMIT 1  -- Get only the first image for the card
                    """, (crop, disease['disease_code']))

                    first_sample = sample_cursor.fetchone()

                    if first_sample:
                        # Create URL for the image
                        disease['sample_image'] = url_for('get_disease_sample_image',
                                                          sample_id=first_sample['id'],
                                                          _external=False)
                        disease['sample_count'] = disease.get('sample_count', 1)
                    else:
                        disease['sample_image'] = url_for('static',
                                                          filename='img/disease-placeholder.jpg')
                        disease['sample_count'] = 0

                except Exception as e:
                    print(f"Error fetching samples: {e}")
                    disease['sample_images'] = []
                    disease['sample_image'] = url_for('static',
                                                      filename='img/disease-placeholder.jpg')
                    disease['sample_count'] = 0
                finally:
                    if sample_cursor:
                        try:
                            sample_cursor.close()
                        except:
                            pass

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
            pending_count = get_pending_count()  # Make sure this function exists

            return render_template(
                'expert/diseases.html',
                diseases=diseases,
                crop=crop,
                crop_display=crop_display,
                crop_stats=crop_stats,
                pagination=pagination,
                pending_count=pending_count
            )

        except Exception as e:
            print(f"Error loading disease library: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Error loading disease library: {str(e)}', 'danger')
            return render_template(
                'expert/diseases.html',
                diseases=[],
                crop='corn',
                crop_display='Corn',
                crop_stats={'corn_count': 0, 'rice_count': 0},
                pagination=None,
                pending_count=0
            )

        finally:
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    # For the diagnosis details endpoint
    @app.route('/api/diagnosis/<int:id>')
    @expert_required
    def api_get_diagnosis_details(id):  # Changed from api_get_diagnosis
        """API endpoint to get diagnosis details for review modal"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            # Get diagnosis details with farmer info
            cur.execute("""
                SELECT dh.*, u.username as farmer_name, u.full_name as farmer_full_name
                FROM diagnosis_history dh
                JOIN users u ON dh.user_id = u.id
                WHERE dh.id = %s
            """, (id,))

            diagnosis = cur.fetchone()

            if not diagnosis:
                return jsonify({'error': 'Diagnosis not found'}), 404

            # Format the response
            response = {
                'id': diagnosis['id'],
                'farmer_name': diagnosis['farmer_full_name'] or diagnosis['farmer_name'],
                'crop': diagnosis['crop'],
                'disease_detected': diagnosis['disease_detected'],
                'symptoms': diagnosis['symptoms'],
                'recommendations': diagnosis['recommendations'],
                'created_at': diagnosis['created_at'].isoformat() if diagnosis['created_at'] else None
            }

            return jsonify(response)

        except Exception as e:
            print(f"Error fetching diagnosis: {e}")
            return jsonify({'error': str(e)}), 500
        finally:
            if cur: cur.close()
            if db: db.close()

    # For the image endpoint
    @app.route('/api/diagnosis/<int:diagnosis_id>/image')
    @expert_required
    def api_get_diagnosis_image(diagnosis_id):  # Changed for clarity
        """Retrieve and display the diagnosis image from database"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor()

            # Get the image blob from database
            cur.execute("SELECT image FROM diagnosis_history WHERE id = %s", (diagnosis_id,))
            result = cur.fetchone()

            if not result or not result[0]:
                # Return a placeholder image
                return send_file('static/img/no-image.png', mimetype='image/png')

            image_data = result[0]

            # Detect image type from first few bytes
            if image_data.startswith(b'\xff\xd8'):
                mimetype = 'image/jpeg'
            elif image_data.startswith(b'\x89PNG\r\n\x1a\n'):
                mimetype = 'image/png'
            elif image_data.startswith(b'GIF87a') or image_data.startswith(b'GIF89a'):
                mimetype = 'image/gif'
            else:
                mimetype = 'application/octet-stream'

            # Return the image directly
            return Response(image_data, mimetype=mimetype)

        except Exception as e:
            print(f"Error retrieving image: {e}")
            # Return a placeholder image on error
            return send_file('static/img/error-image.png', mimetype='image/png')
        finally:
            if cur:
                cur.close()
            if db:
                db.close()

    # ==================== UPLOAD ROUTES ====================
    # Use a single consistent allowed_file function
    def allowed_file(filename):
        """Check if file extension is allowed"""
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    @app.route('/api/upload-disease-image', methods=['POST'])
    @login_required
    @expert_required
    def upload_disease_image():
        """Upload an image for a disease - stores in LONGBLOB with compression"""
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

            # Read and compress the image
            image_data = file.read()

            # Compress image if it's too large
            if file_size > 5 * 1024 * 1024:  # If larger than 5MB
                try:
                    from PIL import Image
                    import io

                    # Open image with PIL
                    img = Image.open(io.BytesIO(image_data))

                    # Convert RGBA to RGB if necessary
                    if img.mode == 'RGBA':
                        img = img.convert('RGB')

                    # Calculate new size (reduce if too large)
                    max_size = (1200, 1200)
                    img.thumbnail(max_size, Image.Resampling.LANCZOS)

                    # Save compressed image
                    output = io.BytesIO()
                    img.save(output, format='JPEG', quality=85, optimize=True)
                    image_data = output.getvalue()

                    print(f"Image compressed from {file_size} to {len(image_data)} bytes")
                except Exception as e:
                    print(f"Compression failed: {e}")
                    # Continue with original if compression fails

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

            db = None
            cursor = None

            try:
                db = get_db()
                cursor = db.cursor()

                if sample_id:
                    # Update existing sample
                    cursor.execute("""
                        UPDATE disease_samples 
                        SET image_data = %s, image_title = %s, image_description = %s, severity_level = %s
                        WHERE id = %s
                    """, (image_data, image_title, image_description, severity, sample_id))
                    new_sample_id = sample_id
                    message = 'Sample updated successfully'
                else:
                    # Get next display order
                    cursor.execute("""
                        SELECT COALESCE(MAX(display_order), 0) + 1 as next_order
                        FROM disease_samples 
                        WHERE crop = %s AND disease_code = %s
                    """, (crop, disease_code))
                    result = cursor.fetchone()
                    next_order = result[0] if result else 1

                    # Insert new sample
                    cursor.execute("""
                        INSERT INTO disease_samples (
                            crop, disease_code, image_data, image_title, 
                            image_description, severity_level, display_order, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    """, (crop, disease_code, image_data, image_title, image_description, severity, next_order))

                    new_sample_id = cursor.lastrowid
                    message = 'Image uploaded successfully'

                db.commit()

                # Generate image URL
                image_url = url_for('get_disease_sample_image', sample_id=new_sample_id, _external=True)

                print(f"✅ Upload successful: sample_id={new_sample_id}")

                return jsonify({
                    'success': True,
                    'sample_id': new_sample_id,
                    'message': message,
                    'image_url': image_url
                })

            except Exception as e:
                print(f"❌ Database error during upload: {e}")
                import traceback
                traceback.print_exc()
                if db:
                    db.rollback()
                return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if db:
                    try:
                        db.close()
                    except:
                        pass

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

            db = get_db()
            cursor = db.cursor()

            # Check if disease code exists in disease_info
            cursor.execute(
                "SELECT id FROM disease_info WHERE disease_code = %s AND crop = %s",
                (data['disease_code'], data['crop'])
            )
            if cursor.fetchone():
                return jsonify({'success': False, 'message': 'Disease code already exists'}), 400

            # Insert into disease_info
            cursor.execute("""
                INSERT INTO disease_info (
                    disease_code, crop, cause, symptoms,
                    organic_treatment, chemical_treatment, prevention, manual_treatment,
                    created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
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

            disease_id = cursor.lastrowid

            # If sample image provided, add to disease_samples
            if data.get('sample_image'):
                cursor.execute("""
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

            db.commit()

            return jsonify({'success': True, 'id': disease_id, 'message': 'Disease added successfully'}), 201

        except Exception as e:
            db.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease/<string:disease_code>', methods=['GET'])
    @login_required
    def get_disease(disease_code):
        """Get disease by disease_code from disease_info with sample images"""
        try:
            crop = request.args.get('crop', 'corn')
            db = get_db()
            cursor = db.cursor(dictionary=True)

            # Get disease info from disease_info table
            cursor.execute("""
                SELECT * FROM disease_info 
                WHERE crop = %s AND disease_code = %s
            """, (crop, disease_code))

            disease = cursor.fetchone()

            if not disease:
                return jsonify({'success': False, 'message': 'Disease not found'}), 404

            # Get sample images from disease_samples - now without image_data
            cursor.execute("""
                SELECT id, image_title, image_description, severity_level, display_order
                FROM disease_samples 
                WHERE crop = %s AND disease_code = %s
                ORDER BY display_order
            """, (crop, disease_code))

            samples = cursor.fetchall()

            # For each sample, create an image URL using the image serving route
            for sample in samples:
                sample['image_url'] = url_for('get_disease_sample_image', sample_id=sample['id'])

            disease['samples'] = samples

            return jsonify({'success': True, 'disease': disease})

        except Exception as e:
            print(f"Error in get_disease: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            if cursor: cursor.close()
            if db: db.close()

    @app.route('/api/disease/<string:disease_code>', methods=['PUT'])
    @login_required
    @expert_required
    def update_disease(disease_code):
        """Update disease in disease_info table"""
        try:
            data = request.json
            crop = data.get('crop', 'corn')
            db = get_db()
            cursor = db.cursor()

            # Check if disease exists
            cursor.execute(
                "SELECT id FROM disease_info WHERE crop = %s AND disease_code = %s",
                (crop, disease_code)
            )
            if not cursor.fetchone():
                return jsonify({'success': False, 'message': 'Disease not found'}), 404

            # Update disease_info
            cursor.execute("""
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
                cursor.execute("""
                    UPDATE disease_samples 
                    SET image_path = %s
                    WHERE crop = %s AND disease_code = %s 
                    ORDER BY display_order LIMIT 1
                """, (
                    data['sample_image'],
                    crop,
                    disease_code
                ))

            db.commit()

            return jsonify({'success': True, 'message': 'Disease updated successfully'})

        except Exception as e:
            db.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease/<string:disease_code>', methods=['DELETE'])
    @login_required
    @expert_required
    def delete_disease(disease_code):
        """Delete disease from both tables"""
        try:
            crop = request.args.get('crop', 'corn')
            db = get_db()
            cursor = db.cursor()

            # First delete from disease_samples
            cursor.execute(
                "DELETE FROM disease_samples WHERE crop = %s AND disease_code = %s",
                (crop, disease_code)
            )

            # Then delete from disease_info
            cursor.execute(
                "DELETE FROM disease_info WHERE crop = %s AND disease_code = %s",
                (crop, disease_code)
            )

            db.commit()

            if cursor.rowcount == 0:
                return jsonify({'success': False, 'message': 'Disease not found'}), 404

            return jsonify({'success': True, 'message': 'Disease deleted successfully'})

        except Exception as e:
            db.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    @app.route('/api/disease-info', methods=['GET'])
    def disease_info():
        """Get disease info for display from disease_info table"""
        try:
            crop = request.args.get('crop')
            disease_code = request.args.get('disease')

            if not crop or not disease_code:
                return jsonify({'success': False, 'message': 'Missing parameters'}), 400

            db = get_db()
            cursor = db.cursor(dictionary=True)

            # Get disease info from disease_info
            cursor.execute("""
                SELECT * FROM disease_info 
                WHERE crop = %s AND disease_code = %s
            """, (crop, disease_code))

            disease = cursor.fetchone()

            if not disease:
                return jsonify({'success': False, 'message': 'Disease not found'}), 404

            # Get all sample images from disease_samples (without the BLOB data)
            cursor.execute("""
                SELECT 
                    id,
                    image_title as title,
                    severity_level as severity,
                    display_order
                FROM disease_samples 
                WHERE crop = %s AND disease_code = %s
                ORDER BY display_order
            """, (crop, disease_code))

            samples = cursor.fetchall()

            # Create image URLs for each sample
            for sample in samples:
                sample['url'] = url_for('get_disease_sample_image', sample_id=sample['id'])

            # Use disease_code as display name since disease_name doesn't exist
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
        finally:
            if cursor: cursor.close()
            if db: db.close()

    class SimplePagination:
        def __init__(self, page, per_page, total):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page
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
        """Serve disease sample image from BLOB"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor()

            # Get the image data
            cur.execute("""
                SELECT image_data, image_title 
                FROM disease_samples 
                WHERE id = %s
            """, (sample_id,))

            result = cur.fetchone()

            if not result or not result[0]:
                # Return a placeholder if no image
                return send_file('static/img/no-image.png', mimetype='image/png')

            image_data = result[0]

            # Detect image type from first few bytes
            if image_data.startswith(b'\xff\xd8'):
                mimetype = 'image/jpeg'
            elif image_data.startswith(b'\x89PNG\r\n\x1a\n'):
                mimetype = 'image/png'
            elif image_data.startswith(b'GIF87a') or image_data.startswith(b'GIF89a'):
                mimetype = 'image/gif'
            else:
                mimetype = 'application/octet-stream'

            # Return the image directly
            return Response(image_data, mimetype=mimetype)

        except Exception as e:
            print(f"Error retrieving disease sample image: {e}")
            return send_file('static/img/error-image.png', mimetype='image/png')
        finally:
            # CRITICAL: Always close connections
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route('/api/disease-sample/<int:sample_id>', methods=['PUT'])
    @login_required
    @expert_required
    def update_disease_sample(sample_id):
        """Update sample metadata (not the image itself)"""
        db = None
        cursor = None

        try:
            data = request.json
            if not data:
                return jsonify({'success': False, 'message': 'No data provided'}), 400

            db = get_db()
            cursor = db.cursor()

            update_fields = []
            values = []

            # Update only metadata fields, not image_data
            for field in ['image_title', 'image_description', 'severity_level']:
                if field in data:
                    update_fields.append(f"{field} = %s")
                    values.append(data[field])

            if not update_fields:
                return jsonify({'success': False, 'message': 'No fields to update'}), 400

            values.append(sample_id)
            cursor.execute(f"UPDATE disease_samples SET {', '.join(update_fields)} WHERE id = %s", values)
            db.commit()

            return jsonify({'success': True, 'message': 'Sample updated successfully'})

        except Exception as e:
            print(f"Error updating sample: {e}")
            if db:
                db.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    @app.route('/api/disease/<string:disease_code>/samples', methods=['POST'])
    @login_required
    @expert_required
    def add_sample(disease_code):
        """Add a new sample image for a disease (using BLOB)"""
        try:
            data = request.json
            crop = data.get('crop', 'corn')

            db = get_db()
            cursor = db.cursor()

            # Get max display order
            cursor.execute("""
                SELECT MAX(display_order) as max_order 
                FROM disease_samples 
                WHERE crop = %s AND disease_code = %s
            """, (crop, disease_code))
            result = cursor.fetchone()
            next_order = (result[0] or 0) + 1

            # For BLOB storage, we need to handle image data differently
            # This route might need to accept a file upload instead of JSON
            # Alternatively, you could first upload the image to a temporary file

            cursor.execute("""
                INSERT INTO disease_samples (
                    disease_code, crop, image_data, image_title,
                    severity_level, display_order, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """, (
                disease_code,
                crop,
                data.get('image_data'),  # This should be binary data
                data.get('image_title', ''),
                data.get('severity_level', 'Moderate'),
                next_order
            ))

            sample_id = cursor.lastrowid
            db.commit()

            return jsonify({
                'success': True,
                'id': sample_id,
                'image_url': url_for('get_disease_sample_image', sample_id=sample_id),
                'message': 'Sample added successfully'
            }), 201

        except Exception as e:
            db.rollback()
            print(f"Error adding sample: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            if cursor: cursor.close()
            if db: db.close()

    @app.route('/api/disease-sample/<int:sample_id>', methods=['DELETE'])
    @login_required
    @expert_required
    def delete_disease_sample(sample_id):
        """Delete a disease sample"""
        db = None
        cursor = None

        try:
            db = get_db()
            cursor = db.cursor()

            cursor.execute("DELETE FROM disease_samples WHERE id = %s", (sample_id,))
            db.commit()

            return jsonify({'success': True, 'message': 'Sample deleted successfully'})

        except Exception as e:
            print(f"Error deleting sample: {e}")
            if db:
                db.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    # ========== ADMIN DISEASE LIBRARY ==========
    @app.route("/admin/disease-library")
    @login_required
    @admin_required
    def admin_disease_library():
        try:
            crop = request.args.get('crop', 'corn')
            page = request.args.get('page', 1, type=int)
            per_page = 12

            db = get_db()
            cur = db.cursor(dictionary=True)

            offset = (page - 1) * per_page

            # FIXED: Removed image_path from query since it doesn't exist
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

            # FIXED: For each disease, get sample count but NOT image_path
            # Instead, we'll create image URLs using the serving route
            for disease in diseases:
                cur.execute("""
                    SELECT id 
                    FROM disease_samples 
                    WHERE crop = %s AND disease_code = %s 
                    ORDER BY display_order LIMIT 1
                """, (crop, disease['disease_code']))
                sample = cur.fetchone()
                if sample:
                    # Create URL to serve the image from BLOB
                    disease['sample_image'] = url_for('get_disease_sample_image', sample_id=sample['id'])
                else:
                    disease['sample_image'] = None

            # Get crop statistics
            cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'corn'")
            corn_count = cur.fetchone()['count'] or 0
            cur.execute("SELECT COUNT(*) as count FROM disease_info WHERE crop = 'rice'")
            rice_count = cur.fetchone()['count'] or 0
            crop_stats = {'corn_count': corn_count, 'rice_count': rice_count}

            # Get sidebar stats
            cur.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 0")
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

            cur.close()
            db.close()

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
        finally:
            # Ensure connections are closed even if error occurs
            if 'cur' in locals() and cur:
                try:
                    cur.close()
                except:
                    pass
            if 'db' in locals() and db:
                try:
                    db.close()
                except:
                    pass
    # ========== HELPER FUNCTION ==========

    @app.context_processor
    def inject_pending_count():
        """Make pending_count available to all expert templates automatically"""
        if session.get('user_type') == 'expert':
            db = None
            cur = None
            try:
                db = get_db()
                cur = db.cursor(dictionary=True)

                # SIMPLE COUNT - no expert_id needed
                cur.execute(
                    "SELECT COUNT(*) as count FROM diagnosis_history WHERE expert_review_status = 'pending' OR expert_review_status IS NULL")
                result = cur.fetchone()
                count = result['count'] if result else 0

                return {'pending_count': count}
            except Exception as e:
                print(f"Error getting pending count: {e}")
                return {'pending_count': 0}
            finally:
                if cur:
                    cur.close()
                if db:
                    db.close()
        return {'pending_count': 0}

    def save_diagnosis_to_history(user_id, crop, disease_detected, confidence,
                                  image_path, symptoms, recommendations, location=None):
        """Save diagnosis to history table"""
        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor()

            cur.execute("""
                INSERT INTO diagnosis_history 
                (user_id, crop, disease_detected, confidence, image_path, 
                 symptoms, recommendations, location)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, crop, disease_detected, confidence, image_path,
                  symptoms, recommendations, location or session.get('location')))

            db.commit()
            return cur.lastrowid

        except Exception as e:
            print(f"Error saving diagnosis to history: {e}")
            return None
        finally:
            if cur:
                try:
                    cur.close()
                except:
                    pass
            if db:
                try:
                    db.close()
                except:
                    pass

    return app