package com.hive.udf;

import com.hive.udf.function.Encrypt;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest
class HiveUdfApplicationTests {
	@Test
	void contextLoads(){
		String data = "genie";
		assertThat(Encrypt.decryptAES256(Encrypt.encryptAES256(data)))
								.isEqualTo(data);
	}
}
