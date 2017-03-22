package com.zulily.vdx.dao;

import com.zulily.vdx.model.PrivateKeyModel;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;

import java.util.List;

public class PrivateKeyDAO extends AbstractDAO<PrivateKeyModel> {
    public PrivateKeyDAO(SessionFactory factory) {
        super(factory);
    }

    public List<PrivateKeyModel> findAS2Id(String as2Id) {
        Criteria criteria = criteria().add(
                Restrictions.eq("as2Id", as2Id)
        );
        List<PrivateKeyModel> result = list(criteria);
        return result;
    }

}
