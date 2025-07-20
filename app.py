# app.py - Application Flask principale
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import sqlite3
import os
import re
import hashlib
import socket
import threading
import json
from datetime import datetime, timedelta
import subprocess
import platform
from werkzeug.utils import secure_filename
import magic
from collections import defaultdict, Counter

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Créer le dossier uploads s'il n'existe pas
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# AJOUT : Fonction pour injecter la date dans tous les templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Configuration de la base de données
DATABASE = 'cyberguard.db'

def init_db():
    """Initialise la base de données avec les tables nécessaires"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Table pour les analyses de logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            total_lines INTEGER,
            suspicious_activities INTEGER,
            threats_detected TEXT,
            analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    ''')
    
    # Table pour les scans réseau
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            open_ports TEXT,
            vulnerabilities TEXT,
            risk_score INTEGER,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table pour la détection de malware
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            threat_level TEXT,
            detection_details TEXT,
            analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

class LogAnalyzer:
    """Classe pour analyser les logs et détecter les menaces"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'brute_force': [
                r'Failed password for',
                r'authentication failure',
                r'Invalid user',
                r'Connection closed by.*port 22'
            ],
            'sql_injection': [
                r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
                r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%23)|(#))',
                r'union.*select',
                r'drop\s+table',
                r'insert\s+into',
                r'delete\s+from'
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>.*?</iframe>'
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'\%2e\%2e\%2f',
                r'\%2e\%2e\%5c'
            ],
            'suspicious_requests': [
                r'GET.*\.(php|asp|jsp|cgi)',
                r'POST.*admin',
                r'GET.*wp-admin',
                r'User-Agent.*sqlmap',
                r'User-Agent.*nikto'
            ]
        }
    
    def analyze_log_file(self, file_path):
        """Analyse un fichier de log et retourne les résultats"""
        results = {
            'total_lines': 0,
            'threats': defaultdict(list),
            'summary': defaultdict(int),
            'timeline': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    results['total_lines'] += 1
                    
                    # Analyser chaque ligne pour les patterns suspects
                    for threat_type, patterns in self.suspicious_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                results['threats'][threat_type].append({
                                    'line': line_num,
                                    'content': line.strip(),
                                    'pattern': pattern
                                })
                                results['summary'][threat_type] += 1
                                break
        
        except Exception as e:
            results['error'] = str(e)
        
        return results

class NetworkScanner:
    """Classe pour scanner les réseaux et détecter les vulnérabilités"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        self.vulnerable_services = {
            21: 'FTP - Risque de connexion non sécurisée',
            23: 'Telnet - Protocole non chiffré',
            25: 'SMTP - Possible relais ouvert',
            1433: 'MSSQL - Base de données exposée',
            3306: 'MySQL - Base de données exposée',
            3389: 'RDP - Risque de brute force',
            5432: 'PostgreSQL - Base de données exposée'
        }
    
    def scan_host(self, host, timeout=3):
        """Scanne un hôte pour les ports ouverts"""
        open_ports = []
        vulnerabilities = []
        
        for port in self.common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    open_ports.append(port)
                    if port in self.vulnerable_services:
                        vulnerabilities.append(self.vulnerable_services[port])
                
                sock.close()
            except Exception:
                continue
        
        # Calculer le score de risque
        risk_score = len(vulnerabilities) * 20 + len(open_ports) * 5
        risk_score = min(risk_score, 100)
        
        return {
            'open_ports': open_ports,
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_score
        }

class MalwareDetector:
    """Classe pour détecter les malwares dans les fichiers"""
    
    def __init__(self):
        self.suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js']
        self.malware_signatures = [
            b'TVqQAAMAAAAEAAAA',  # PE header
            b'PK\x03\x04',  # ZIP header (peut contenir des malwares)
            b'\x7fELF',  # ELF header
        ]
        self.suspicious_strings = [
            'eval(',
            'exec(',
            'system(',
            'shell_exec(',
            'passthru(',
            'base64_decode(',
            'wget',
            'curl',
            'powershell',
            'cmd.exe'
        ]
    
    def analyze_file(self, file_path):
        """Analyse un fichier pour détecter les malwares"""
        results = {
            'threat_level': 'LOW',
            'detections': [],
            'file_info': {}
        }
        
        try:
            # Informations sur le fichier
            file_stats = os.stat(file_path)
            results['file_info'] = {
                'size': file_stats.st_size,
                'extension': os.path.splitext(file_path)[1].lower()
            }
            
            # Calculer le hash
            with open(file_path, 'rb') as f:
                file_content = f.read()
                results['file_info']['hash'] = hashlib.md5(file_content).hexdigest()
            
            # Vérifier l'extension
            if results['file_info']['extension'] in self.suspicious_extensions:
                results['detections'].append('Extension de fichier suspecte')
                results['threat_level'] = 'HIGH'
            
            # Vérifier les signatures
            for signature in self.malware_signatures:
                if signature in file_content:
                    results['detections'].append('Signature de malware détectée')
                    results['threat_level'] = 'CRITICAL'
                    break
            
            # Vérifier les chaînes suspectes
            file_text = file_content.decode('utf-8', errors='ignore')
            for suspicious_string in self.suspicious_strings:
                if suspicious_string in file_text:
                    results['detections'].append(f'Chaîne suspecte trouvée: {suspicious_string}')
                    if results['threat_level'] == 'LOW':
                        results['threat_level'] = 'MEDIUM'
            
            # Taille de fichier suspecte
            if results['file_info']['size'] > 50 * 1024 * 1024:  # 50MB
                results['detections'].append('Fichier de taille importante')
                if results['threat_level'] == 'LOW':
                    results['threat_level'] = 'MEDIUM'
        
        except Exception as e:
            results['error'] = str(e)
        
        return results

# Initialisation des analyseurs
log_analyzer = LogAnalyzer()
network_scanner = NetworkScanner()
malware_detector = MalwareDetector()

@app.route('/')
def index():
    """Page d'accueil avec le dashboard"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Statistiques générales
    cursor.execute('SELECT COUNT(*) FROM log_analysis')
    total_log_analysis = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM network_scans')
    total_network_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM malware_analysis')
    total_malware_analysis = cursor.fetchone()[0]
    
    # Dernières analyses
    cursor.execute('SELECT filename, analysis_date, suspicious_activities FROM log_analysis ORDER BY analysis_date DESC LIMIT 5')
    recent_logs = cursor.fetchall()
    
    cursor.execute('SELECT target_ip, scan_date, risk_score FROM network_scans ORDER BY scan_date DESC LIMIT 5')
    recent_scans = cursor.fetchall()
    
    cursor.execute('SELECT filename, analysis_date, threat_level FROM malware_analysis ORDER BY analysis_date DESC LIMIT 5')
    recent_malware = cursor.fetchall()
    
    conn.close()
    
    return render_template('index.html', 
                         total_log_analysis=total_log_analysis,
                         total_network_scans=total_network_scans,
                         total_malware_analysis=total_malware_analysis,
                         recent_logs=recent_logs,
                         recent_scans=recent_scans,
                         recent_malware=recent_malware)

@app.route('/log-analyzer')
def log_analyzer_page():
    """Page d'analyse de logs"""
    return render_template('log_analyzer.html')

@app.route('/upload-log', methods=['POST'])
def upload_log():
    """Upload et analyse d'un fichier de log"""
    if 'log_file' not in request.files:
        flash('Aucun fichier sélectionné', 'error')
        return redirect(url_for('log_analyzer_page'))
    
    file = request.files['log_file']
    if file.filename == '':
        flash('Aucun fichier sélectionné', 'error')
        return redirect(url_for('log_analyzer_page'))
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Analyser le fichier
        results = log_analyzer.analyze_log_file(file_path)
        
        # Sauvegarder dans la base
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO log_analysis (filename, total_lines, suspicious_activities, threats_detected, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, results['total_lines'], sum(results['summary'].values()), 
              json.dumps(dict(results['summary'])), json.dumps(results['threats'])))
        conn.commit()
        conn.close()
        
        # Nettoyer le fichier temporaire
        os.remove(file_path)
        
        flash('Analyse terminée avec succès!', 'success')
        return render_template('log_results.html', results=results, filename=filename)

@app.route('/network-scanner')
def network_scanner_page():
    """Page du scanner réseau"""
    return render_template('network_scanner.html')

@app.route('/scan-network', methods=['POST'])
def scan_network():
    """Effectuer un scan réseau"""
    target_ip = request.form.get('target_ip')
    
    if not target_ip:
        flash('Adresse IP requise', 'error')
        return redirect(url_for('network_scanner_page'))
    
    # Valider l'adresse IP
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        flash('Adresse IP invalide', 'error')
        return redirect(url_for('network_scanner_page'))
    
    # Effectuer le scan
    results = network_scanner.scan_host(target_ip)
    
    # Sauvegarder dans la base
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO network_scans (target_ip, open_ports, vulnerabilities, risk_score)
        VALUES (?, ?, ?, ?)
    ''', (target_ip, json.dumps(results['open_ports']), 
          json.dumps(results['vulnerabilities']), results['risk_score']))
    conn.commit()
    conn.close()
    
    flash('Scan terminé avec succès!', 'success')
    return render_template('network_results.html', results=results, target_ip=target_ip)

@app.route('/malware-detector')
def malware_detector_page():
    """Page du détecteur de malware"""
    return render_template('malware_detector.html')

@app.route('/upload-file', methods=['POST'])
def upload_file():
    """Upload et analyse d'un fichier pour détection de malware"""
    if 'file' not in request.files:
        flash('Aucun fichier sélectionné', 'error')
        return redirect(url_for('malware_detector_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Aucun fichier sélectionné', 'error')
        return redirect(url_for('malware_detector_page'))
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Analyser le fichier
        results = malware_detector.analyze_file(file_path)
        
        # Sauvegarder dans la base
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO malware_analysis (filename, file_hash, file_size, threat_level, detection_details)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, results['file_info'].get('hash', ''), 
              results['file_info'].get('size', 0), results['threat_level'], 
              json.dumps(results['detections'])))
        conn.commit()
        conn.close()
        
        # Nettoyer le fichier temporaire
        os.remove(file_path)
        
        flash('Analyse terminée avec succès!', 'success')
        return render_template('malware_results.html', results=results, filename=filename)

@app.route('/history')
def history():
    """Page d'historique des analyses"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Récupérer l'historique de toutes les analyses
    cursor.execute('SELECT "log" as type, filename, analysis_date, suspicious_activities as score FROM log_analysis UNION ALL SELECT "network" as type, target_ip, scan_date, risk_score FROM network_scans UNION ALL SELECT "malware" as type, filename, analysis_date, threat_level FROM malware_analysis ORDER BY analysis_date DESC')
    history_data = cursor.fetchall()
    
    conn.close()
    
    return render_template('history.html', history=history_data)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)