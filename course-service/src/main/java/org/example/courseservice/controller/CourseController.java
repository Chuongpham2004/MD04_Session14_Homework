package org.example.courseservice.controller;

import org.example.courseservice.dto.Course;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/courses")
public class CourseController {

    // Dữ liệu giả (static list) - không dùng Database
    private final List<Course> courses = new CopyOnWriteArrayList<>(List.of(
            new Course(1L, "Java Core", "Nguyen Van A"),
            new Course(2L, "Spring Boot Microservices", "Tran Thi B"),
            new Course(3L, "ReactJS", "Le Van C")
    ));
    private final AtomicLong nextId = new AtomicLong(4);

    @GetMapping
    @PreAuthorize("hasAuthority('STUDENT') or hasAuthority('INSTRUCTOR')")
    public List<Course> getAll() {
        return new ArrayList<>(courses);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('INSTRUCTOR')")
    public Course create(@RequestBody Course request) {
        Course course = new Course(nextId.getAndIncrement(), request.name(), request.instructor());
        courses.add(course);
        return course;
    }
}
