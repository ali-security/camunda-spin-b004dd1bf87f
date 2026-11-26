/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.fasterxml.jackson.databind.views;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * Regression tests for GHSA-mhm7-754m-9p8w (jackson-databind #6054) against the
 * shaded jackson-databind: {@code @JsonView} must be honored for polymorphic
 * properties that use an EXTERNAL_PROPERTY type id.
 *<p>
 * A {@code @JsonView} never changes the type id, so these tests check the two
 * distinct things a view CAN do -- (a) hide the whole polymorphic property (left
 * null), or (b) hide a field of the resolved subtype (subtype built, field left
 * null) -- across the different ways such a property gets bound:
 *<pre>
 *  (1) property-based (@JsonCreator) constructor, property hidden      -&gt; null
 *  (2) field of the resolved subtype hidden (property-based creator)   -&gt; field null
 *  (3) type id is ITSELF a creator param, only the value hidden        -&gt; value null, type id kept
 *  (4) default-constructor bean (eager binding), property hidden       -&gt; null
 *  (5) @JsonPOJOBuilder-based bean, property hidden                    -&gt; null
 *  (6) reverse of (3): type id creator param hidden, value visible     -&gt; value kept, type id null
 *  (7) default-constructor bean, scalar "natural" value bound without
 *      a type id at end-of-object, property hidden                     -&gt; null
 *</pre>
 */
// [databind#6054]: Honor `@JsonView` for external-type-id (`EXTERNAL_PROPERTY`) properties
public class JsonViewExternalTypeIdBypassTest
{
    static class PublicView { }
    static class AdminView extends PublicView { }

    static abstract class Asset {
        public String name;
    }

    static class PublicAsset extends Asset { }

    static class AdminAsset extends Asset {
        public String secret;
    }

    // Subtype used by case (2): here the admin-only marker is on the field, not
    // on the owning property.
    static class FieldGatedAdminAsset extends Asset {
        @JsonView(AdminView.class)
        public String secret;
    }

    // Case (1): the entire polymorphic property is admin-only.
    static class PropertyGatedContainer {
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "kind")
        @JsonSubTypes({
                @JsonSubTypes.Type(value = PublicAsset.class, name = "pub"),
                @JsonSubTypes.Type(value = AdminAsset.class, name = "admin")
        })
        @JsonView(AdminView.class)
        public Asset asset;

        public String label;

        @JsonCreator
        public PropertyGatedContainer(
                @JsonProperty("label") String label,
                @JsonProperty("asset") @JsonView(AdminView.class) Asset asset) {
            this.label = label;
            this.asset = asset;
        }
    }

    // Case (2): the property is always visible, but the resolved subtype has an
    // admin-only field.
    static class FieldGatedContainer {
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "kind")
        @JsonSubTypes({
                @JsonSubTypes.Type(value = PublicAsset.class, name = "pub"),
                @JsonSubTypes.Type(value = FieldGatedAdminAsset.class, name = "admin")
        })
        public Asset asset;

        public String label;

        @JsonCreator
        public FieldGatedContainer(
                @JsonProperty("label") String label,
                @JsonProperty("asset") Asset asset) {
            this.label = label;
            this.asset = asset;
        }
    }

    // Case (3): like case (1), but the external type id "kind" is ITSELF a creator
    // parameter ([databind#999]). The value "asset" is admin-only, but "kind" carries
    // no view, so hiding the value must not also drop the (visible) type id property.
    static class TypeIdCreatorContainer {
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "kind",
                visible = true)
        @JsonSubTypes({
                @JsonSubTypes.Type(value = PublicAsset.class, name = "pub"),
                @JsonSubTypes.Type(value = AdminAsset.class, name = "admin")
        })
        @JsonView(AdminView.class)
        public Asset asset;

        public String label;
        public String kind;

        @JsonCreator
        public TypeIdCreatorContainer(
                @JsonProperty("label") String label,
                @JsonProperty("kind") String kind,
                @JsonProperty("asset") @JsonView(AdminView.class) Asset asset) {
            this.label = label;
            this.kind = kind;
            this.asset = asset;
        }
    }

    // Case (4): admin-only external-type property on a default-constructor (no
    // @JsonCreator) bean -- exercises the other ExternalTypeHandler.complete() path.
    static class DefaultCtorContainer {
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "kind")
        @JsonSubTypes({
                @JsonSubTypes.Type(value = PublicAsset.class, name = "pub"),
                @JsonSubTypes.Type(value = AdminAsset.class, name = "admin")
        })
        @JsonView(AdminView.class)
        public Asset asset;

        public String label;
    }

    // Case (5): admin-only external-type property on a @JsonPOJOBuilder-based bean --
    // exercises the BuilderBasedDeserializer external-type path.
    @JsonDeserialize(builder = BuilderContainer.Builder.class)
    static class BuilderContainer {
        public final String label;
        public final Asset asset;

        BuilderContainer(String label, Asset asset) {
            this.label = label;
            this.asset = asset;
        }

        @JsonPOJOBuilder(withPrefix = "with")
        static class Builder {
            String label;
            Asset asset;

            public Builder withLabel(String label) {
                this.label = label;
                return this;
            }

            @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                    include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                    property = "kind")
            @JsonSubTypes({
                    @JsonSubTypes.Type(value = PublicAsset.class, name = "pub"),
                    @JsonSubTypes.Type(value = AdminAsset.class, name = "admin")
            })
            @JsonView(AdminView.class)
            public Builder withAsset(Asset asset) {
                this.asset = asset;
                return this;
            }

            public BuilderContainer build() {
                return new BuilderContainer(label, asset);
            }
        }
    }

    // Case (6): reverse of (3) -- the type id "kind" is a creator parameter carrying
    // the view, while the value "asset" is visible. Under PublicView the value must
    // still be bound and resolve correctly (the type id string still drives type
    // resolution), but the hidden "kind" creator parameter must be left null.
    static class TypeIdGatedContainer {
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "kind",
                visible = true)
        @JsonSubTypes({
                @JsonSubTypes.Type(value = PublicAsset.class, name = "pub"),
                @JsonSubTypes.Type(value = AdminAsset.class, name = "admin")
        })
        public Asset asset;

        public String label;
        public String kind;

        @JsonCreator
        public TypeIdGatedContainer(
                @JsonProperty("label") String label,
                @JsonProperty("kind") @JsonView(AdminView.class) String kind,
                @JsonProperty("asset") Asset asset) {
            this.label = label;
            this.kind = kind;
            this.asset = asset;
        }
    }

    // Case (7): admin-only external-type property of a "natural" type on a
    // default-constructor bean. A scalar value sent WITHOUT any type id is bound
    // directly at end-of-object (ExternalTypeHandler.complete(), [databind#118]),
    // without going through the eager per-property binding.
    static class NaturalValueContainer {
        @JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "kind")
        @JsonView(AdminView.class)
        public Object value;

        public String label;
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Case (1): admin-only polymorphic property must NOT be bound when reading
    // with the less-privileged PublicView. A view never rewrites the type id, so
    // the only correct outcome is that "asset" is skipped entirely (left null).
    @Test
    public void testViewGatedExternalTypeProperty() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'LEAKED'}}");

        PropertyGatedContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(PropertyGatedContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        // Admin-only property hidden from PublicView -> not bound at all
        assertNull("Admin-only 'asset' must not be bound under PublicView", result.asset);
    }

    // Sanity check: with the AdminView active, the same property IS bound, and
    // resolves to AdminAsset (the type id is "admin").
    @Test
    public void testViewGatedExternalTypePropertyVisibleForAdmin() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'shh'}}");

        PropertyGatedContainer result = MAPPER.readerWithView(AdminView.class)
                .forType(PropertyGatedContainer.class)
                .readValue(json);

        assertTrue("Expected AdminAsset, got " + result.asset,
                result.asset instanceof AdminAsset);
        AdminAsset asset = (AdminAsset) result.asset;
        assertEquals("foo", asset.name);
        assertEquals("shh", asset.secret);
    }

    // Case (2): the property itself is always visible, so the type id "admin"
    // correctly produces the admin subtype -- but its admin-only "secret" field
    // must be left out when reading with PublicView.
    @Test
    public void testViewGatedFieldOfExternalTypeSubtype() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'LEAKED'}}");

        FieldGatedContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(FieldGatedContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        // View does not change the type id: still the admin subtype...
        assertTrue("Expected FieldGatedAdminAsset, got " + result.asset,
                result.asset instanceof FieldGatedAdminAsset);
        FieldGatedAdminAsset asset = (FieldGatedAdminAsset) result.asset;
        assertEquals("foo", asset.name);
        // ...but the admin-only field must not leak under PublicView
        assertNull("Admin-only 'secret' must not leak under PublicView", asset.secret);
    }

    // Case (3): hiding the admin-only value must NOT drop the (non-view) type id
    // property when the type id is itself a creator parameter ([databind#999]).
    @Test
    public void testViewGatedValueKeepsVisibleTypeIdCreatorProp() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'LEAKED'}}");

        TypeIdCreatorContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(TypeIdCreatorContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        // Admin-only value is hidden...
        assertNull("Admin-only 'asset' must not be bound under PublicView", result.asset);
        // ...but the visible type id creator property must still be bound
        assertEquals("Visible type id 'kind' must still be bound", "admin", result.kind);
    }

    // Case (4): admin-only external-type property on a default-constructor bean must
    // also be skipped under PublicView (covers the other complete() overload).
    @Test
    public void testViewGatedExternalTypePropertyDefaultCtor() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'LEAKED'}}");

        DefaultCtorContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(DefaultCtorContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        assertNull("Admin-only 'asset' must not be bound under PublicView", result.asset);
    }

    // Case (5): admin-only external-type property on a @JsonPOJOBuilder bean must be
    // skipped under PublicView (covers the BuilderBasedDeserializer external-type path).
    @Test
    public void testViewGatedExternalTypePropertyBuilder() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'LEAKED'}}");

        BuilderContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(BuilderContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        assertNull("Admin-only 'asset' must not be bound under PublicView", result.asset);
    }

    // Case (6): reverse of case (3) -- @JsonView on the type-id creator param but not
    // the value. Under PublicView the value is still bound (and resolves to the admin
    // subtype via the type id), but the hidden type-id property must be left null.
    @Test
    public void testViewGatedTypeIdCreatorPropKeepsVisibleValue() throws Exception
    {
        String json = a2q("{'label':'hello','kind':'admin',"
                + "'asset':{'name':'foo','secret':'shh'}}");

        TypeIdGatedContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(TypeIdGatedContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        // Value carries no view -> still bound, and the type id still selects the subtype
        assertTrue("Expected AdminAsset, got " + result.asset,
                result.asset instanceof AdminAsset);
        AdminAsset asset = (AdminAsset) result.asset;
        assertEquals("foo", asset.name);
        // ...but the admin-only type id creator property must not be bound
        assertNull("Admin-only type id 'kind' must not be bound under PublicView", result.kind);
    }

    // Case (7): admin-only "natural" (scalar, no type id) external-type value on a
    // default-constructor bean must be skipped under PublicView too.
    @Test
    public void testViewGatedExternalTypeNaturalValueDefaultCtor() throws Exception
    {
        String json = a2q("{'label':'hello','value':'LEAKED'}");

        NaturalValueContainer result = MAPPER.readerWithView(PublicView.class)
                .forType(NaturalValueContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        assertNull("Admin-only 'value' must not be bound under PublicView", result.value);
    }

    // Sanity check for case (7): with the AdminView active the natural value IS bound.
    @Test
    public void testViewGatedExternalTypeNaturalValueVisibleForAdmin() throws Exception
    {
        String json = a2q("{'label':'hello','value':'shh'}");

        NaturalValueContainer result = MAPPER.readerWithView(AdminView.class)
                .forType(NaturalValueContainer.class)
                .readValue(json);

        assertEquals("hello", result.label);
        assertEquals("shh", result.value);
    }

    private static String a2q(String json) {
        return json.replace('\'', '"');
    }
}
