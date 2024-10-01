package com.springsecurity.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;

import javax.sql.DataSource;
import javax.xml.crypto.Data;

//Need to explicitly declare that we are using external db unlike inmemory h2-database
@Configuration
public class DataSourceConfig {

    @Autowired
    private DataSource dataSource;

    public DataSourceInitializer dataSourceInitializer(){
        DataSourceInitializer initializer = new DataSourceInitializer();
    }
}
