import os
from .pcap_scanner import analyze_pcap
from .portscanner import*
from flask import Flask, render_template,request, session

global_result = {}

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route("/", methods=['GET', 'POST'])
    def index(error = None) :
        if error is not None:
            return render_template('index.html', error = error)
        else :
            return render_template('index.html', error = None)
    
    @app.route("/uploads", methods=['POST'])
    def uploads():
        if 'pcap' not in request.files:
            error = 'No file part'
            return index(error)
                
        pcap_file = request.files['pcap']
        if pcap_file.filename == '':
            error = 'No selected file'
            return index(error)

        if pcap_file and allowed_file(pcap_file.filename):
            filename = pcap_file.filename
            save_path = os.path.join(app.instance_path, filename)
            pcap_file.save(save_path)
                
            result = analyze_pcap(save_path)
            filename = os.path.basename(result['file_name'])
            result['file_name'] = filename
            session.pop('result', None)
            session['result'] = result
            return results(result)
        else:
            error = 'Invalid file type. Only .pcap and .pcapng files are allowed.'
            return index(error)
    

    @app.route("/scan-port", methods=['POST'])
    def scan_port():
        target_ip = request.form.get('target')
        start_port = int(request.form.get('start-port'))
        end_port = int(request.form.get('end-port'))
        
        if not target_ip or start_port < 0 or end_port < 0 or start_port > 65535 or end_port > 65535 or start_port > end_port:
            error = "Invalid input. Please ensure the IP address and port range are correct."
            return render_template('index.html', error=error)
        
        result = scanHost(target_ip, start_port, end_port)
    
        session['result'] = result
        
        return render_template('scan_result.html', result=result)
    
    @app.route("/scan-network", methods=['POST'])
    def scan_network():
        target_ip = request.form.get('network')
        result = network_scan(target_ip)
    
        session['result'] = result
        
        return render_template('network_result.html', result=result)


    @app.route("/results", methods=['GET'])
    def results(result):
        return render_template('results.html', result=result)
    
    @app.route("/dns", methods=['GET'])
    def dns():
        session_result = session.get('result',{})
        return render_template('dns.html', result=session_result)
    
    @app.route("/pcap", methods=['GET'])
    def pcap():
        return render_template('pcap.html')
    
    @app.route("/pcap-home", methods=['GET'])
    def pcap_home():
        return render_template('pcap-home.html')
    
    @app.route("/port", methods=['GET'])
    def port():
        return render_template('port.html')
    
    @app.route("/port-home", methods=['GET'])
    def port_home():
        return render_template('port-home.html')
    
    @app.route("/cara-export-pcap", methods=['GET'])
    def cara_export_pcap():
        return render_template('pcap-tutorial.html')
    
    @app.route("/udp", methods=['GET'])
    def udp():
        return render_template('udp.html')
    
    @app.route("/tcp", methods=['GET'])
    def tcp():
        return render_template('tcp.html')
    
    @app.route("/icmp", methods=['GET'])
    def icmp():
        return render_template('icmp.html')
        
    @app.route("/http", methods=['GET'])
    def http():
        return render_template('http.html')
    
    @app.route("/recom-sql-injection", methods=['GET'])
    def recom_sql():
        return render_template('recom_sql_inject.html')
    
    @app.route("/recom-ddos", methods=['GET'])
    def recom_ddos():
        return render_template('recom_ddos.html')
    
    @app.route("/recom-bruteforce", methods=['GET'])
    def recom_bruteforce():
        return render_template('recom_bruteforce.html')
    
    @app.route("/recom-arp-spoof", methods=['GET'])
    def recom_arp_spoof():
        return render_template('recom_arp_spoof.html')
    
    @app.route("/recom-port-scan", methods=['GET'])
    def recom_port_scan():
        return render_template('recom_port_scan.html')
        
    @app.route('/details/<vulnerability_type>')
    def details(vulnerability_type):
        session_result = session.get('result', {})
        vulnerabilities = session_result.get('vulnerabilities', [])
        vulnerability_details = []

        for vulnerability in vulnerabilities:
            if vulnerability['vulnerability_type'] == vulnerability_type and 'details' in vulnerability:
                vulnerability_details = vulnerability['details']
                break

        return render_template('details.html', details=vulnerability_details, vulnerability_type=vulnerability_type)

    def allowed_file(filename):
        allowed_extensions = {'pcap', 'pcapng'}
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

    return app