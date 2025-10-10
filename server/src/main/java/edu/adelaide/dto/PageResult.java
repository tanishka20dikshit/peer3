package edu.adelaide.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class PageResult<T> {
  private int page;
  private int size;
  private long total;
  private List<T> items;

  public PageResult() {}
  public PageResult(int page, int size, long total, List<T> items) {
    this.page = page; this.size = size; this.total = total; this.items = items;
  }

}
