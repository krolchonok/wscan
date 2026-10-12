import os,signal,subprocess,tempfile,threading,json,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from playwright.sync_api import sync_playwright
repo=Path(__file__).resolve().parents[1]
binary=os.environ.get("WSCAN_TEST_BINARY",str(repo/"wscan"))
artifacts=Path(os.environ.get("WSCAN_UX_ARTIFACTS","/tmp/wscan-web-ux"))
artifacts.mkdir(parents=True,exist_ok=True)
class Fixture(BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'<html><title>Local fixture</title></html>'
  self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
http_fixture=HTTPServer(('127.0.0.1',0),Fixture)
threading.Thread(target=http_fixture.serve_forever,daemon=True).start()
port=http_fixture.server_address[1]
with tempfile.TemporaryDirectory(prefix='wscan-web-browser-') as directory:
 env={**os.environ,'XDG_CONFIG_HOME':directory}
 process=subprocess.Popen([binary,'serve','--listen','127.0.0.1:0'],cwd=repo,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  line=process.stdout.readline().strip()
  assert line.startswith('Web: '),line
  url=line[5:]
  with sync_playwright() as p:
   browser=p.chromium.launch(headless=True)
   page=browser.new_page(viewport={'width':1440,'height':1000})
   errors=[]
   page.on('pageerror',lambda error:errors.append(str(error)))
   page.goto(url)
   page.get_by_role('heading',name='Начните с проекта').wait_for()
   assert '#token=' not in page.url
   page.get_by_role('button',name='Создать проект',exact=True).last.click()
   page.get_by_label('Название',exact=True).fill('Local browser check')
   page.locator('input[name=targets]').fill('127.0.0.1')
   page.locator('#active-form').get_by_role('button',name='Создать проект',exact=True).click()
   page.get_by_role('heading',name='Local browser check',exact=True).wait_for()
   page.get_by_role('button',name='Начать проверку',exact=True).click()
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.get_by_text('Дополнительные параметры',exact=True).click()
   page.locator('#ports').fill(str(port))
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.get_by_role('button',name='Запустить проверку',exact=True).click()
   page.locator('#job-list').get_by_text('Завершена',exact=True).wait_for(timeout=30000)
   page.get_by_role('button',name='Хосты',exact=True).click()
   page.locator('#rows').get_by_role('button',name='Открыть',exact=True).wait_for()
   assert str(port) in page.locator('#rows').inner_text()
   # Service with no native module must leave the catalogue open.
   page.locator('#rows').get_by_role('button',name='Открыть',exact=True).click()
   page.get_by_role('button',name='Действия',exact=True).click()
   page.get_by_role('button',name='Открыть проверки',exact=True).click()
   page.get_by_role('heading',name='Проверки проекта',exact=True).wait_for()
   assert page.locator('#dialog').is_visible()
   page.get_by_role('button',name='Закрыть окно',exact=True).click()
   page.get_by_role('button',name='Результаты',exact=True).click()
   for export_format in ['json','html','csv']:
    page.locator('#export-format').select_option(export_format)
    with page.expect_download() as download_info:
     page.get_by_role('button',name='Экспорт запуска',exact=True).click()
    download=download_info.value
    assert download.suggested_filename.endswith('.'+export_format)
    destination=artifacts/('fixture-report.'+export_format)
    download.save_as(destination)
    assert destination.stat().st_size>0
   page.get_by_role('button',name='Настройки проекта',exact=True).click()
   # Untouched lockout defaults must not make the form invalid.
   page.get_by_role('button',name='Сохранить настройки',exact=True).click()
   page.locator('#dialog').wait_for(state='hidden')
   page.get_by_role('button',name='Как пользоваться',exact=True).click()
   page.get_by_role('heading',name='Первый запуск',exact=True).wait_for()
   assert 'несколько IP' in page.locator('#content').inner_text()
   page.get_by_role('button',name='Обзор',exact=True).click()
   # Empty checks selection should fail in the wizard, before starting a job.
   page.get_by_role('button',name='Начать проверку',exact=True).click()
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.locator('input[name=profile][value=checks]').check()
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.locator('#dialog-error').wait_for(state='visible')
   assert 'Сначала выберите проверки' in page.locator('#dialog-error').inner_text()
   page.get_by_role('button',name='Закрыть окно',exact=True).click()
   page.get_by_role('button',name='Обзор',exact=True).click()
   page.screenshot(path=str(artifacts/'overview.png'),full_page=True)
   page.get_by_role('button',name='Доступы',exact=True).click()
   page.get_by_role('button',name='Добавить учётку',exact=True).click()
   page.get_by_label('Имя',exact=True).fill('fixture-reader')
   page.get_by_label('Пароль или хеш',exact=True).fill('fixture-secret')
   page.get_by_role('button',name='Сохранить учётку',exact=True).click()
   page.get_by_text('fixture-reader',exact=True).wait_for()
   assert 'fixture-secret' not in page.locator('#content').inner_text()
   # Local two-host AD launch: no CIDR conversion and no outside targets.
   page.locator('#new-project').click()
   page.get_by_label('Название',exact=True).fill('Two local AD hosts')
   page.locator('input[name=targets]').fill('127.0.0.2 127.0.0.3')
   page.locator('#active-form').get_by_role('button',name='Создать проект',exact=True).click()
   page.get_by_role('heading',name='Two local AD hosts',exact=True).wait_for()
   page.get_by_role('button',name='Начать проверку',exact=True).click()
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.locator('input[name=profile][value=ad-scan]').check()
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.get_by_role('button',name='Запустить проверку',exact=True).click()
   page.locator('#job-list').get_by_text('Завершена',exact=True).wait_for(timeout=30000)
   jobs=page.evaluate('async()=>await (await fetch("/api/jobs")).json()')
   ad=next(job for job in jobs if job['kind']=='ad-scan')
   assert ad['targets']==['127.0.0.2','127.0.0.3'],ad['targets']
   page.locator('#project-select').select_option(label='Local browser check')
   page.get_by_role('button',name='Обзор',exact=True).click()
   page.get_by_role('heading',name='Local browser check',exact=True).wait_for()
   # Cancel via UI, with a deliberately slow local discovery.
   page.get_by_role('button',name='Настройки проекта',exact=True).click()
   page.locator('input[name=DiscoveryRPS]').fill('10')
   page.get_by_role('button',name='Сохранить настройки',exact=True).click()
   page.locator('#dialog').wait_for(state='hidden')
   page.get_by_role('button',name='Начать проверку',exact=True).click()
   page.locator('#scan-scope').fill('127.0.0.2')
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.get_by_text('Дополнительные параметры',exact=True).click()
   page.locator('#ports').fill(','.join(str(x) for x in range(20000,20040)))
   page.get_by_role('button',name='Продолжить',exact=True).click()
   page.get_by_role('button',name='Запустить проверку',exact=True).click()
   page.locator('#job-list').get_by_role('button',name='Остановить',exact=True).click()
   page.locator('#job-list').get_by_text('Отменена',exact=True).wait_for(timeout=15000)
   page.reload()
   page.get_by_role('button',name='Задачи',exact=True).click()
   page.locator('#job-list').get_by_text('Отменена',exact=True).wait_for(timeout=15000)
   page.get_by_role('button',name='Полный TUI в браузере',exact=True).click()
   page.locator('#terminal').get_by_text('Local browser check',exact=False).wait_for(timeout=15000)
   page.locator('#terminal').press('Enter')
   page.locator("#terminal").get_by_text("Обзор проекта",exact=False).wait_for(timeout=15000)
   page.screenshot(path=str(artifacts/'terminal.png'),full_page=True)
   page.get_by_role('button',name='Закрыть сеанс',exact=True).click()
   page.get_by_role('heading',name='Local browser check',exact=True).wait_for()
   page.set_viewport_size({'width':360,'height':800})
   assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'mobile document overflow'
   page.screenshot(path=str(artifacts/'mobile.png'),full_page=True)
   assert not errors,errors
   browser.close()
  print('Web UX passed: onboarding, local discovery, catalogue, empty-check guidance, settings defaults, JSON/HTML/CSV downloads, help, two-host AD, cancel/reconnect, credentials, embedded TUI, mobile; no JS errors.')
 finally:
  process.send_signal(signal.SIGINT)
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:process.kill();process.wait()
  assert process.returncode==0,process.stderr.read()
http_fixture.shutdown()
