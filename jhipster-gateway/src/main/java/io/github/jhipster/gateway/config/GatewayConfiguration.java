package io.github.jhipster.gateway.config;

import io.github.jhipster.gateway.gateway.ratelimiting.RateLimitingFilter;
import io.github.jhipster.gateway.gateway.ratelimiting.RateLimitingRepository;
import io.github.jhipster.gateway.gateway.accesscontrol.AccessControlFilter;
import io.github.jhipster.gateway.gateway.responserewriting.SwaggerBasePathRewritingFilter;

import javax.inject.Inject;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Session;

@Configuration
public class GatewayConfiguration {

    @Configuration
    public static class SwaggerBasePathRewritingConfiguration {

        @Bean
        public SwaggerBasePathRewritingFilter swaggerBasePathRewritingFilter(){
            return new SwaggerBasePathRewritingFilter();
        }
    }

    @Configuration
    public static class AccessControlFilter {

        @Bean
        public AccessControlFilter accessControlFilter(){
            return new AccessControlFilter();
        }
    }

    /**
     * Configures the Zuul filter that limits the number of API calls per user.
     * <p>
     * For this filter to work, you need to have:
     * <p><ul>
     * <li>A working Cassandra cluster
     * <li>A schema with the JHipster rate-limiting tables configured, using the
     * "create_keyspace.cql" and "create_tables.cql" scripts from the
     * "src/main/resources/config/cql" directory
     * <li>Your cluster configured in your application-*.yml files, using the
     * "spring.data.cassandra" keys
     * <li>Spring Data Cassandra running, by removing in your application-*.yml the
     * "spring.autoconfigure.exclude" key that excludes the Cassandra and Spring Data
     * Cassandra auto-configuration.
     * </ul><p>
     */
    @Configuration
    @ConditionalOnProperty("jhipster.gateway.rate-limiting.enabled")
    public static class RateLimitingConfiguration {

        @Inject
        private JHipsterProperties jHipsterProperties;

        @Bean
        public RateLimitingRepository rateLimitingRepository() {
            return new RateLimitingRepository();
        }

        @Bean
        public RateLimitingFilter rateLimitingFilter() {
            return new RateLimitingFilter(rateLimitingRepository(), jHipsterProperties);
        }
    }
}
