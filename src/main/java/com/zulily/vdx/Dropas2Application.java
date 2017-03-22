package com.zulily.vdx;

import com.zulily.vdx.dao.PrivateKeyDAO;
import com.zulily.vdx.dao.PublicKeyDAO;
import com.zulily.vdx.model.PrivateKeyModel;
import com.zulily.vdx.model.PublicKeyModel;
import com.zulily.vdx.resources.AS2Resource;
import io.dropwizard.Application;
import io.dropwizard.db.DataSourceFactory;
import io.dropwizard.hibernate.HibernateBundle;
import io.dropwizard.migrations.MigrationsBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Dropas2Application extends Application<Dropas2Configuration> {

    private final HibernateBundle<Dropas2Configuration> hibernate = new HibernateBundle<Dropas2Configuration>(PrivateKeyModel.class, PublicKeyModel.class) {
        @Override
        public DataSourceFactory getDataSourceFactory(Dropas2Configuration configuration) {
            return configuration.database;
        }
    };

    public static void main(final String[] args) throws Exception {
        new Dropas2Application().run(args);
    }

    @Override
    public String getName() {
        return "dropas2";
    }

    @Override
    public void initialize(final Bootstrap<Dropas2Configuration> bootstrap) {
        Security.addProvider(new BouncyCastleProvider());
        bootstrap.addBundle(new MigrationsBundle<Dropas2Configuration>() {
            @Override
            public DataSourceFactory getDataSourceFactory(Dropas2Configuration configuration) {
                return configuration.database;
            }
        });
        bootstrap.addBundle(hibernate);
    }

    @Override
    public void run(final Dropas2Configuration configuration,
                    final Environment environment) {
        final PrivateKeyDAO privateKeyDAO = new PrivateKeyDAO(hibernate.getSessionFactory());
        final PublicKeyDAO publicKeyDAO = new PublicKeyDAO(hibernate.getSessionFactory());
        AS2Resource as2Resource = new AS2Resource(privateKeyDAO, publicKeyDAO);
        environment.jersey().register(as2Resource);
    }

}
