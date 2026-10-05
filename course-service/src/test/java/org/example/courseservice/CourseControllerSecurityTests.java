package org.example.courseservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "eureka.client.enabled=false")
@AutoConfigureMockMvc
class CourseControllerSecurityTests {

    private static final String ROLE_HEADER = "X-User-Role";
    private static final String NEW_COURSE = "{\"name\":\"Docker\",\"instructor\":\"Pham Van D\"}";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void noRoleHeader_returns401() throws Exception {
        mockMvc.perform(get("/api/courses")).andExpect(status().isUnauthorized());
    }

    @Test
    void studentCanListCourses() throws Exception {
        mockMvc.perform(get("/api/courses").header(ROLE_HEADER, "STUDENT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("Java Core"));
    }

    @Test
    void otherRoleCannotListCourses_returns403() throws Exception {
        mockMvc.perform(get("/api/courses").header(ROLE_HEADER, "ROLE_USER"))
                .andExpect(status().isForbidden());
    }

    @Test
    void studentCannotCreate_returns403() throws Exception {
        mockMvc.perform(post("/api/courses").header(ROLE_HEADER, "STUDENT")
                        .contentType(MediaType.APPLICATION_JSON).content(NEW_COURSE))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.roles[0]").value("STUDENT"));
    }

    @Test
    void instructorCanCreate_returns201() throws Exception {
        mockMvc.perform(post("/api/courses").header(ROLE_HEADER, "INSTRUCTOR")
                        .contentType(MediaType.APPLICATION_JSON).content(NEW_COURSE))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(4))
                .andExpect(jsonPath("$.name").value("Docker"));
    }
}
