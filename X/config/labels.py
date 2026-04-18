LABELS = ['normal', 'injection', 'xss', 'ssrf', 'path_traversal', 'auth_attack', 'recon', 'api_abuse']

LABEL_MAPPING = {
    'normal': 0,
    'injection': 1,
    'xss': 2,
    'ssrf': 3,
    'path_traversal': 4,
    'auth_attack': 5,
    'recon': 6,
    'api_abuse': 7
}

ATTACK_TO_LABEL = {
    'sql': 'injection',
    'nosql': 'injection',
    'command': 'injection',
    'xpath': 'injection',
    'xss': 'xss',
    'ssrf': 'ssrf',
    'path_traversal': 'path_traversal',
    'lfi': 'path_traversal',
    'rfi': 'path_traversal',
    'auth_bypass': 'auth_attack',
    'session_hijack': 'auth_attack',
    'brute_force': 'auth_attack',
    'port_scan': 'recon',
    'dir_enum': 'recon',
    'vuln_scan': 'recon',
    'api_abuse': 'api_abuse',
    'normal': 'normal'
}