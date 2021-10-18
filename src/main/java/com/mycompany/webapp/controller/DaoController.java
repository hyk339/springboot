package com.mycompany.webapp.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.mycompany.webapp.dto.Board;
import com.mycompany.webapp.dto.Pager;
import com.mycompany.webapp.service.BoardService;

import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/dao")
@Slf4j
public class DaoController {
	@Resource
	private BoardService boardService;
	
	@RequestMapping("/content")
	public String content() {
		log.info("실행");
		return "dao/content";
	}
	
	@RequestMapping("/boardList")
	public String boardList(@RequestParam(defaultValue="1") int pageNo, Model model) {
	   log.info("실행");
	   
	   int totalRows = boardService.getTotalBoardNum();
	   if(totalRows < 1000) {
	      for(int i=1; i<=1000; i++) {
	         Board board = new Board();
	         board.setBtitle("제목"+i);
	         board.setBcontent("내용"+i);
	         board.setMid("user");
	         boardService.writeBoard(board);
	      }
	   }
	   
	   totalRows = boardService.getTotalBoardNum();
	   Pager pager = new Pager(5, 5, totalRows, pageNo);   
	   model.addAttribute("pager", pager);
	   
	   List<Board> boards = boardService.getBoards(pager);
	   model.addAttribute("boards", boards);
	   return "dao/boardList";
	}
	
	@GetMapping("/boardWriteForm")
	public String boardWriteForm() {
	   log.info("실행");
	   return "dao/boardWriteForm";
	}
	
	@PostMapping("/boardWrite")
	public String boardWrite(Board board) throws Exception {
	   log.info("실행");
	   
	   //form에서 입력을 안하고 보내도 null이 아니다. 비어있는 객체가 온다.
	   //boardWriterForm에 input으로 있고 값이 없으면 비어있는 객체가 온다.
	   if(board.getBattach() != null && !board.getBattach().isEmpty()) {
		  MultipartFile mf = board.getBattach();
		  board.setBattachoname(mf.getOriginalFilename());
		  board.setBattachsname(new Date().getTime()+"-"+mf.getOriginalFilename());
		  board.setBattachtype(mf.getContentType());
		  File file = new File("C:/hyundai_ite/upload_files/"+board.getBattachsname());
		  mf.transferTo(file);
	   }
	   
	   boardService.writeBoard(board);
	   
	   return "redirect:/dao/boardList";
	}
	
	@GetMapping("/boardDetail")
	public String boardDetail(int bno, Model model) {
	   log.info("실행");
	   Board board = boardService.getBoard(bno);
	   model.addAttribute("board", board);
	   return "dao/boardDetail";
	}
	
	//responsebody보다 아래 void가 더 효율적이다. 
	@GetMapping("/battachDownload")
	public void battachDownload(int bno, HttpServletResponse response) throws Exception {
		Board board = boardService.getBoard(bno);
        String battachoname = board.getBattachoname();
        if(battachoname == null) return;
        
        
        //아래가 필요한 이유 -> 
        battachoname = new String(battachoname.getBytes("UTF-8"),"ISO-8859-1");
        String battachsname = board.getBattachsname();      
        String battachspath = "C:/hyundai_ite/upload_files/" + battachsname;
        String battachtype = board.getBattachtype();
  
        //아래가 필요한 이유 -> 브라우저가 보여줄수 있는 파일은 브라우져가 보여준다. 그런데 보여주지 말고 다운로드가 되도록 하기 위해서
        //무조건 파일로 받고 싶으면 아래를 넣어라.
        response.setHeader("Content-Disposition", "attachment; filename=\""+battachoname+"\";");
        //response의 타입을 넣어주는 것이다.
        response.setContentType(battachtype);

        InputStream is = new FileInputStream(battachspath);
        OutputStream os = response.getOutputStream();
        FileCopyUtils.copy(is, os);
        is.close();
        os.flush();
        os.close();
	}
	
	@GetMapping("/boardUpdateForm")
	public String boardUpdateForm(int bno, Model model) {
	   log.info("실행");
	   Board board = boardService.getBoard(bno);
	   model.addAttribute("board", board);
	   return "dao/boardUpdateForm";
	}
	
	
}
