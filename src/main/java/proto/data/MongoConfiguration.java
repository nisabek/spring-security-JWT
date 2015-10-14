package proto.data;

import com.mongodb.MongoClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;

@Configuration
public class MongoConfiguration extends AbstractMongoConfiguration{
        @Bean
        public MongoClient mongo() throws Exception {
            return new MongoClient("localhost");
        }

        @Override
        public String getDatabaseName() {
            return "prototype";
        }
}
