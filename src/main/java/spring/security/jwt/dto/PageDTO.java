package spring.security.jwt.dto;

import java.util.List;

/**
 * @author star
 */
public class PageDTO<T> {

    private int totalPage;

    private List<T> data;

    public static <T> PageDTO<T> of(int totalPage, List<T> data) {
        PageDTO<T> tPageDTO = new PageDTO<>();
        tPageDTO.setTotalPage(totalPage);
        tPageDTO.setData(data);

        return tPageDTO;
    }

    public int getTotalPage() {
        return totalPage;
    }

    public void setTotalPage(int totalPage) {
        this.totalPage = totalPage;
    }

    public List<T> getData() {
        return data;
    }

    public void setData(List<T> data) {
        this.data = data;
    }
}
