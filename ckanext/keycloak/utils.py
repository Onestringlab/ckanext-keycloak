import jwt
import requests

from flask import jsonify

from sqlalchemy import or_
from ckan.logic import get_action
from ckan.plugins import toolkit as tk
from ckan.model import Package, User, Group, Member, meta

def query_custom(query, params=None):
    """
    Helper function untuk menjalankan query ke database CKAN.
    """
    session = meta.Session
    result = session.execute(query, params or {})
    return result.fetchall()

def get_username(jwt_token):
    try:
        # Dekode JWT tanpa memvalidasi signature dan expiration
        decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})

        # Extract the preferred_username
        email = decoded_token.get("email")
        preferred_username = decoded_token.get("preferred_username")

        # Jika sukses, kembalikan decoded token
        return preferred_username,email

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token sudah kedaluwarsa"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Token tidak valid: {str(e)}"}), 400

def get_profile_by_username(username):
    query = '''
                SELECT id, name, apikey, fullname, email, reset_key, sysadmin, 
                    activity_streams_email_notifications, state, plugin_extras, image_url 
                FROM public.user 
                WHERE name = :username
                LIMIT 1
            '''
    result = query_custom(query, {'username': username})

    # Konversi hasil query menjadi daftar dictionary
    row = result[0]
    data = {
            "id": row[0],
            "name": row[1],
            "apikey": row[2],
            "fullname": row[3],
            "email": row[4],
            "reset_key": row[5],
            "sysadmin": row[6],
            "activity_streams_email_notifications": row[7],
            "state": row[8],
            "plugin_extras": row[9],
            "image_url": row[10]
        }
    return data

def validate_token(api_url, accessToken):
    try:
        if not accessToken:
            return False
        api_url_token = f"{api_url}/auth/validate-token?token={accessToken}"
        response = requests.post(api_url_token)
        if response.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        return False
