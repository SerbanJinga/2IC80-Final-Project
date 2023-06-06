from Functions import Functions
functions = Functions()
functions_result = functions.retrieveMACAdress("enp0s3", "192.168.56.101")

print(functions_result)


from ARPStart import ARPStart

arpStart = ARPStart("enp0s3", "192.168.56.101", "192.168.56.102", False)
arpStart.startARP()
