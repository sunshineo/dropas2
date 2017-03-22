package com.zulily.vdx.dao;

import com.zulily.vdx.model.PublicKeyModel;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;

import java.util.List;

public class PublicKeyDAO extends AbstractDAO<PublicKeyModel> {
    public PublicKeyDAO(SessionFactory factory) {
        super(factory);
    }

    public List<PublicKeyModel> findAS2Id(String as2Id) {
        Criteria criteria = criteria().add(
                Restrictions.eq("as2Id", as2Id)
        );
        List<PublicKeyModel> result = list(criteria);
        return result;
    }

}
