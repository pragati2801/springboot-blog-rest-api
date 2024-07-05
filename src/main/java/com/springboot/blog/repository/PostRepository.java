package com.springboot.blog.repository;

import com.springboot.blog.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;

//no need to add @repository coz simplejparepository class implements jpaRepository and it uses @Repository

public interface  PostRepository  extends JpaRepository<Post, Long> {

}
