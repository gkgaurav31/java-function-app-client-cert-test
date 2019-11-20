package com.function;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.xml.bind.DatatypeConverter;

import com.microsoft.azure.functions.annotation.*;
import com.microsoft.azure.functions.*;

/**
 * Azure Functions with HTTP Trigger.
 */
public class Function {
	/**
	 * This function listens at endpoint "/api/HttpTrigger-Java". Two ways to invoke it using "curl" command in bash:
	 * 1. curl -d "HTTP Body" {your host}/api/HttpTrigger-Java&code={your function key}
	 * 2. curl "{your host}/api/HttpTrigger-Java?name=HTTP%20Query&code={your function key}"
	 * Function Key is not needed when running locally, it is used to invoke function deployed to Azure.
	 * More details: https://aka.ms/functions_authorization_keys
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 */
	@FunctionName("HttpTrigger-Java")
	public HttpResponseMessage run(
			@HttpTrigger(name = "req", methods = {HttpMethod.GET, HttpMethod.POST}, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
			final ExecutionContext context)  {
		context.getLogger().info("Java HTTP trigger processed a request.");

		// Parse query parameter
		Map<String, String> headers = request.getHeaders();
		context.getLogger().info("The headers are: " + Arrays.asList(headers));
		String certB64 = headers.get("x-arr-clientcert");
		
		String thumbprint = "";
		
		try {
			byte encodedCert[] = Base64.getDecoder().decode(certB64);
			ByteArrayInputStream inputStream  =  new ByteArrayInputStream(encodedCert);

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inputStream);

			thumbprint = DatatypeConverter.printHexBinary(
					MessageDigest.getInstance("SHA-1").digest(
							cert.getEncoded())).toLowerCase();
			 
			 context.getLogger().info("Thumbprint is: " + thumbprint);
			 
		}catch(Exception e) {
			context.getLogger().info("In exception " + e.getMessage());
			e.getMessage();
		}
		

		return request.createResponseBuilder(HttpStatus.OK).body("Headers: " + Arrays.asList(headers) + "\n\nEncoded String: "+ certB64 + "\n\nThumbprint:  " + thumbprint ).build();
		
	}
}
