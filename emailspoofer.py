import mechanize
 
def main_email_spoofer(sender_name,sender_mail,recipient_mail,subject,content):
	
	br = mechanize.Browser()
	 
	# fromname= raw_input("Enter the name of the sender: ")
	# frommail= raw_input("Enter the fake sender mail-id: ")
	# to = raw_input("Enter the recipient address: ")
	# subject = raw_input("Enter the subject: ")
	# message = raw_input(">")

	fromname= sender_name
	frommail= sender_mail
	to = recipient_mail
	subject = subject
	message = content
	 
	#proxy = "http://127.0.0.1:8080"
	 
	url = "http://hellfire.bplaced.de/"
	headers = "Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)"
	br.addheaders = [('User-agent', headers)]
	br.open(url)
	br.set_handle_equiv(True)
	br.set_handle_gzip(True)
	br.set_handle_redirect(True)
	br.set_handle_referer(True)
	br.set_handle_robots(False)
	br.set_debug_http(False)
	br.set_debug_redirects(False)
	#br.set_proxies({"http": proxy})
	 
	br.select_form(nr=0)
	# print br.form
	 
	br.form['tbname']=fromname
	br.form['tbfrom']=frommail
	br.form['tbto'] = to
	br.form['tbsubject'] = subject
	br.form['area2'] = message
	 
	result = br.submit()
	 
	response = br.response().read()
	 
	 
	if "E-Mail successfully sent." in response:
	    print "The email has been sent successfully!!"
	else:
	    print "Failed to send email!"