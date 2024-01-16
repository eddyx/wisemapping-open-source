/*
 *    Copyright [2022] [wisemapping]
 *
 *   Licensed under WiseMapping Public License, Version 1.0 (the "License").
 *   It is basically the Apache License, Version 2.0 (the "License") plus the
 *   "powered by wisemapping" text requirement on every single page;
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the license at
 *
 *       http://www.wisemapping.org/license
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package com.wisemapping.dao;

import com.wisemapping.model.Label;
import com.wisemapping.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository("labelManager")
public class LabelManagerImpl
        implements LabelManager {
    @Autowired
    private EntityManager entityManager;

    @Override
    public void addLabel(@NotNull final Label label) {
        saveLabel(label);
    }

    @Override
    public void saveLabel(@NotNull final Label label) {
        entityManager.persist(label);
    }

    @NotNull
    @Override
    public List<Label> getAllLabels(@NotNull final User user) {
        final TypedQuery<Label> query = entityManager.createQuery("from com.wisemapping.model.Label wisemapping where creator=:creatorId", Label.class);
        query.setParameter("creatorId", user);
        return query.getResultList();
    }

    @Nullable
    @Override
    public Label getLabelById(int id, @NotNull final User user) {
        final TypedQuery<Label> query = entityManager.createQuery("from com.wisemapping.model.Label wisemapping where id=:id and creator=:creator", Label.class);
        query.setParameter("id", id);
        query.setParameter("creator", user);

        final List<Label> resultList = query.getResultList();
        return getFirst(resultList);
    }

    @Nullable
    @Override
    public Label getLabelByTitle(@NotNull String title, @NotNull final User user) {
        final TypedQuery<Label> query = entityManager.createQuery("from com.wisemapping.model.Label wisemapping where title=:title and creator=:creator", Label.class);
        query.setParameter("title", title);
        query.setParameter("creator", user);
        return query.getResultList().stream().findFirst().orElse(null);
    }

    @Override
    public void removeLabel(@NotNull Label label) {
        entityManager.remove(label);
    }

    @Nullable
    private Label getFirst(final List<Label> labels) {
        Label result = null;
        if (labels != null && !labels.isEmpty()) {
            result = labels.get(0);
        }
        return result;
    }

}
