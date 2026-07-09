package com.globalside.codingchallenge.rbac;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for role based access control on the Products API.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ProductAPISecurityTest {

    private static final String USER = "user";
    private static final String USER_PASS = "userPass";
    private static final String ADMIN = "admin";
    private static final String ADMIN_PASS = "adminPass";

    private static final String NEW_PRODUCT_JSON = """
            {
              "name": "Test Chair",
              "description": "A sturdy test chair",
              "price": 49.99,
              "currency": "EUR",
              "category": "Furniture",
              "brand": "TestBrand",
              "color": "black"
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    // ---------- Anonymous callers, everything is 401 ----------

    @Test
    void anonymousCannotReadProducts() throws Exception {
        mockMvc.perform(get("/products"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void anonymousCannotCreateProducts() throws Exception {
        mockMvc.perform(post("/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(NEW_PRODUCT_JSON))
                .andExpect(status().isUnauthorized());
    }

    // ---------- Wrong credentials, identity fails ----------

    @Test
    void wrongPasswordIsRejectedWith401() throws Exception {
        mockMvc.perform(get("/products").with(httpBasic(ADMIN, "definitelyWrong")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownUsernameIsRejectedWith401() throws Exception {
        mockMvc.perform(get("/products").with(httpBasic("ghost", "whatever")))
                .andExpect(status().isUnauthorized());
    }

    // ---------- USER role, read yes, write no ----------

    @Test
    void userCanListProducts() throws Exception {
        mockMvc.perform(get("/products").with(httpBasic(USER, USER_PASS)))
                .andExpect(status().isOk());
    }

    @Test
    void userCanReadSingleProduct() throws Exception {
        mockMvc.perform(get("/products/1").with(httpBasic(USER, USER_PASS)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1));
    }

    @Test
    void userCannotCreateProduct() throws Exception {
        mockMvc.perform(post("/products")
                        .with(httpBasic(USER, USER_PASS))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(NEW_PRODUCT_JSON))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(
                        "You do not have permission to perform this action."));
    }

    @Test
    void userCannotUpdateProduct() throws Exception {
        mockMvc.perform(put("/products/1")
                        .with(httpBasic(USER, USER_PASS))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(NEW_PRODUCT_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void userCannotDeleteProduct() throws Exception {
        mockMvc.perform(delete("/products/1").with(httpBasic(USER, USER_PASS)))
                .andExpect(status().isForbidden());
    }

    // ---------- ADMIN role, full access ----------

    @Test
    void adminCanListProducts() throws Exception {
        mockMvc.perform(get("/products").with(httpBasic(ADMIN, ADMIN_PASS)))
                .andExpect(status().isOk());
    }

    @Test
    void adminCanCreateUpdateAndDeleteProduct() throws Exception {
        // Create, capture nothing fancy, then update and delete the same row,
        // leaving the shared database file as we found it.
        String location = mockMvc.perform(post("/products")
                        .with(httpBasic(ADMIN, ADMIN_PASS))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(NEW_PRODUCT_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andReturn().getResponse().getContentAsString();

        int createdId = com.jayway.jsonpath.JsonPath.read(location, "$.id");

        mockMvc.perform(put("/products/" + createdId)
                        .with(httpBasic(ADMIN, ADMIN_PASS))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(NEW_PRODUCT_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/products/" + createdId)
                        .with(httpBasic(ADMIN, ADMIN_PASS)))
                .andExpect(status().isOk());
    }
}