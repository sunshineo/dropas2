package com.zulily.vdx;

import io.dropwizard.Configuration;
import io.dropwizard.db.DataSourceFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class Dropas2Configuration extends Configuration {
    @Valid
    @NotNull
    public DataSourceFactory database = new DataSourceFactory();
}
