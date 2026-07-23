'use strict';

function initializeConfirmForms() {
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const message = form.dataset.confirm || '계속할까요?';
      if (!window.confirm(message)) event.preventDefault();
    });
  });
}

function initializeFileInputs() {
  document.querySelectorAll('[data-file-input]').forEach((input) => {
    const container = input.closest('.file-upload-control');
    const nameOutput = container?.querySelector('[data-file-name]');
    input.addEventListener('change', () => {
      if (!nameOutput) return;
      const file = input.files?.[0];
      nameOutput.textContent = file ? file.name : '선택된 파일 없음';
      nameOutput.title = file?.name || '';
    });
  });
}

function initializeSingleSubmitForms() {
  document.querySelectorAll('form[data-single-submit]').forEach((form) => {
    form.addEventListener('submit', () => {
      if (!form.checkValidity()) return;
      const button = form.querySelector('[data-submit-button]');
      if (!button || button.disabled) return;
      button.disabled = true;
      button.dataset.originalText = button.textContent;
      button.textContent = '처리 중…';
    });
  });
}

function initializeBoardViewCounter() {
  const board = document.querySelector('[data-board-view-url]');
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
  if (!board || !csrfToken) return;

  const formData = new FormData();
  formData.set('csrf_token', csrfToken);
  fetch(board.dataset.boardViewUrl, {
    method: 'POST',
    body: formData,
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  })
    .then((response) => {
      if (!response.ok) throw new Error('view-count-failed');
      return response.json();
    })
    .then((payload) => {
      const output = board.querySelector('[data-board-view-count]');
      if (output && Number.isInteger(payload.view_count)) {
        output.textContent = String(payload.view_count);
      }
    })
    .catch(() => {
      // 조회 수 기록 실패는 게시글 열람을 방해하지 않는다.
    });
}

function initializeChatScroll() {
  const messageArea = document.querySelector('[data-chat-scroll]');
  if (messageArea) messageArea.scrollTop = messageArea.scrollHeight;
}

document.addEventListener('DOMContentLoaded', () => {
  initializeConfirmForms();
  initializeFileInputs();
  initializeSingleSubmitForms();
  initializeBoardViewCounter();
  initializeChatScroll();
});
