"""
Vue Infos - Documentation et informations de l'application.
Contient la description de l'application, glossaire et meilleures pratiques.
"""

from infos_view import INFOS_HTML

def get_infos_view():
    """Retourne le template de la vue infos."""
    from flask import render_template_string
    return render_template_string(INFOS_HTML)
