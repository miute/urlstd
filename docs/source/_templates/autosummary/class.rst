{{ fullname | escape | underline}}

.. currentmodule:: {{ module }}

.. autoclass:: {{ objname }}
   :noindex:
   :show-inheritance:

   {% block methods %}
   {% if methods %}
   .. rubric:: {{ _('Methods:') }}

   .. autosummary::
   {% for item in all_methods %}
   {% if item not in inherited_members and item not in ['__format__', '__getnewargs__', '__init__', '__new__', '__repr__'] and (not item.startswith('_') or item.startswith('__')) %}
      ~{{ name }}.{{ item }}
   {% endif %}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block attributes %}
   {% if attributes %}
   .. rubric:: {{ _('Attributes:') }}

   .. autosummary::
   {% for item in attributes %}
   {% if item not in inherited_members %}
      ~{{ name }}.{{ item }}
   {% endif %}
   {%- endfor %}
   {% endif %}
   {% endblock %}
