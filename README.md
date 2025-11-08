# Study Material Safety Analyzer

A lightweight, beginner-friendly web tool that helps students quickly analyze filenames and download links for risky or suspicious study materials (PDFs, ZIPs, notes).  
No backend. No AI. Simple logic-based rules you can extend perfect for a first GitHub project.

## Why this project
Students often download materials from channels and unknown sources. This tool provides fast checks:
- Suspicious file name patterns
- Hidden executable tricks (e.g. `ebook.pdf.exe`)
- Unsafe extensions
- Clickbait / scammy download titles
- Simple website reputation heuristics (local checks)

All logic is in JavaScript and easy to read great to demonstrate security thinking and clean code.

## Features
- Filename checker (multiple dots, suspicious keywords, extension check)
- URL analyzer (HTTPS check, domain heuristics, redirect params)
- Simple site safety score (local heuristic)
- Beginner-friendly code + comments

## Realistic Test Samples
✅ Safe Filenames

DBMS_Unit3_Notes.pdf

OperatingSystem_Assignment1.docx

DSA_Exam_Important_Questions.pdf

MCA_Sem2_Python_LabManual.pdf

CyberSecurity_Notes_2025.pdf

Nashik_University_PYQ_2024.pdf

⚠️ Suspicious Filenames

notes_finalversion.pdf

Book_free_download_now.pdf.exe

Hacked_PremiumBook.zip

study-material-unlocked-free.rar

ImportantQuestions_pdf_download.exe

PracticeProblems.docx.scr

Java_Handwritten_notes.rar.exe

🌐 Safe URLs

https://www.mit.edu/courses/6.0001/notes.pdf

https://nashikuniversity.ac.in/uploads/notes/dbms.pdf

❌ Suspicious URLs

http://freebook-download-fast.com/notes_finalversion.pdf

https://studymaterial-secure-fast-download.net/file?id=72391

http://drive-download-free.in/redirect=book-free

## How to run
1. Clone the repo:
   ```bash
  git clone https://github.com/Namratadandgawal/study-material-safety-analyzer.git
