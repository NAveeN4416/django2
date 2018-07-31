from django.core.files.storage import FileSystemStorage
from django.template.loader import render_to_string,get_template
from django.http import HttpResponse
from xhtml2pdf import pisa
from io import BytesIO
from django import template


class Generate:

	def PDF(template_src,context={},ref_id=""):
		try:
			template_src = get_template(template_src)
		except template.TemplateDoesNotExist:
			return 0
				
		html     = template_src.render(context)
		result   = BytesIO()
		pdf      = pisa.pisaDocument(BytesIO(html.encode('ISO-8859-1')),result)
		if not pdf.err:
			return result
		else:
			return 0

	def CSV(template_src,ref_id):
		pass		


