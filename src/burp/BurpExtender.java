package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;

/**
 * 敏感信息探测
 * 
 * @author dream9
 *
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
	// 查找的关键字
	private final String[] keys = { "pwd", "passwd", "password", "salt",
			"mima", "secret" };
	// 扩展名称
	private final String NAME = "Hawkeye";
	private PrintWriter stdout;
	private IExtensionHelpers helper;
	private IBurpExtenderCallbacks callback;

	private DefaultTableModel model;

	public IRequestInfo iRequestInfo;
	public IResponseInfo iResponseInfo;

	private JPanel jPanel_top;
	private JTabbedPane jTabbedPane;
	private JScrollPane jScrollPane;
	private JSplitPane jSplitPaneV;

	private JTable jsonTable;

	private JPanel jPanel_reqInfo_left;
	private JPanel jPanel_respInfo_right;
	private JSplitPane jSplitPaneInfo;
	private ITextEditor iRequestTextEditor;
	private ITextEditor iResponseTextEditor;

	private int count = 0;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callback = callbacks;
		this.helper = callbacks.getHelpers();
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		callbacks.setExtensionName("Hawkeye-敏感信息探测--->Created by dream9");
		this.stdout.println(NAME + "插件安装成功--->Created by dream9");

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {

				// 初始化垂直分隔面板
				jSplitPaneV = new JSplitPane(JSplitPane.VERTICAL_SPLIT, true);
				// 获取电脑屏幕尺寸(可以使用其他Component替代)
				Dimension screenSize = Toolkit.getDefaultToolkit()
						.getScreenSize();
				// 设置分割条位置
				jSplitPaneV.setDividerLocation(screenSize.height / 3);
				jSplitPaneV.setOneTouchExpandable(true);

				// 垂直分隔面板的顶部
				jPanel_top = new JPanel();
				// 设置垂直分隔面板顶部的子控件
				// 放置表格控件
				jTabbedPane = new JTabbedPane();

				// 初始化 Burp 提供的 ITextEditor 编辑器接口
				iRequestTextEditor = callback.createTextEditor();
				iRequestTextEditor.setEditable(false);

				iResponseTextEditor = callback.createTextEditor();
				iResponseTextEditor.setEditable(false);

				String[] columns = { "#", "Host", "Method", "URL", "Comment",
						"Request", "Response" };
				model = new DefaultTableModel(null, columns);

				// 初始化 jsonTable
				jsonTable = new JTable(model);
				// 隐藏Request和Response列
				jsonTable.getColumnModel().getColumn(6).setMinWidth(0);
				jsonTable.getColumnModel().getColumn(6).setMaxWidth(0);
				jsonTable.getColumnModel().getColumn(5).setMinWidth(0);
				jsonTable.getColumnModel().getColumn(5).setMaxWidth(0);

				// 滚动条容器
				JScrollPane jScrollPane1 = new JScrollPane(jsonTable);
				// 设置最佳尺寸(方便滚动条的及时出现)
				jScrollPane1.setPreferredSize(new Dimension(300, 100));
				jScrollPane1
						.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
				jScrollPane1
						.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
				jTabbedPane.addTab("敏感信息探测", jScrollPane1);
				jScrollPane = new JScrollPane(jTabbedPane);
				jScrollPane
						.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
				jScrollPane
						.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
				jPanel_top.add(jScrollPane, BorderLayout.CENTER);
				jPanel_top.setLayout(null);

				jsonTable.addMouseListener(new MouseAdapter() {
					@Override
					public void mouseClicked(MouseEvent e) {
						int row = jsonTable.getSelectedRow();
						iRequestTextEditor.setText(null);
						iResponseTextEditor.setText(null);
						iRequestTextEditor.setText((jsonTable
								.getValueAt(row, 5)).toString().getBytes());
						iResponseTextEditor.setText((jsonTable.getValueAt(row,
								6)).toString().getBytes());
					}
				});

				// 添加componentResized事件 否则在改变Burp 主窗口大小时会错位
				jPanel_top.addComponentListener(new ComponentListener() {

					@Override
					public void componentShown(ComponentEvent e) {
					}

					@Override
					public void componentResized(ComponentEvent e) {
						if (e.getSource() == jPanel_top) {
							jScrollPane.setSize(jPanel_top.getSize().width - 5,
									jPanel_top.getSize().height - 5);
							jScrollPane.setSize(
									jPanel_top.getSize().width - 10,
									jPanel_top.getSize().height - 10);
						}
					}

					@Override
					public void componentMoved(ComponentEvent e) {
						// TODO Auto-generated method stub
					}

					@Override
					public void componentHidden(ComponentEvent e) {
						// TODO Auto-generated method stub
					}
				});

				// 设置垂直分隔面板底部的子控件
				// 显示请求/响应 信息的水平分隔面板初始化
				jSplitPaneInfo = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
						true);
				jSplitPaneInfo.setDividerLocation(screenSize.width / 2 - 50);
				jSplitPaneInfo.setOneTouchExpandable(true);

				// 初始化 请求，响应信息显示 面板
				jPanel_reqInfo_left = new JPanel();
				jPanel_respInfo_right = new JPanel();

				jPanel_reqInfo_left.setLayout(new BorderLayout());
				jPanel_respInfo_right.setLayout(new BorderLayout());

				// 将 Burp 提供的 ITextEditor 编辑器 添加到请求，响应信息显示 面板中
				jPanel_reqInfo_left.add(iRequestTextEditor.getComponent(),
						BorderLayout.CENTER);
				jPanel_respInfo_right.add(iResponseTextEditor.getComponent(),
						BorderLayout.CENTER);

				// 分别添加 请求，响应信息显示 面板 到 垂直分隔面板底部
				jSplitPaneInfo.add(jPanel_reqInfo_left, JSplitPane.LEFT);
				jSplitPaneInfo.add(jPanel_respInfo_right, JSplitPane.RIGHT);

				// 最后为垂直分隔面板添加顶部面板和水平分隔面板
				jSplitPaneV.add(jPanel_top, JSplitPane.TOP);
				jSplitPaneV.add(jSplitPaneInfo, JSplitPane.BOTTOM);

				// 设置自定义组件并添加标签
				callback.customizeUiComponent(jSplitPaneV);
				callback.addSuiteTab(BurpExtender.this);
			}
		});

		callbacks.registerHttpListener(this);
	}

	// 实现 ITab 接口的 getTabCaption 方法
	@Override
	public String getTabCaption() {
		return NAME;
	}

	// 实现 ITab 接口的 getUiComponent 方法
	@Override
	public Component getUiComponent() {
		return jSplitPaneV;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest,
			IHttpRequestResponse messageInfo) {
		IRequestInfo request = null;
		IResponseInfo response = null;

		String pro = "";
		String host = "";
		String method = "";
		int port = 0;
		String path = "";
		String data[] = new String[7];
		if (messageInfo != null) {
			if (!messageIsRequest) {
				IHttpService httpService = messageInfo.getHttpService();
				byte[] req = messageInfo.getRequest();
				byte[] res = messageInfo.getResponse();
				request = helper.analyzeRequest(req);
				response = helper.analyzeResponse(res);

				String mime = response.getStatedMimeType();
				if (mime != null && mime.equals("JSON")) {
					List<String> headers = request.getHeaders();
					pro = httpService.getProtocol();
					host = httpService.getHost();
					method = request.getMethod();
					port = httpService.getPort();
					String firstHeader = headers.get(0);
					path = firstHeader.substring(firstHeader.indexOf(" ") + 1,
							firstHeader.lastIndexOf(" ")); // 请求的路径

					String resData = new String(res).substring(response
							.getBodyOffset());

					String url = "";
					if (port == 80 || port == 443) {
						url = pro + "://" + host + path;
					} else {
						url = pro + "://" + host + ":" + port + path;
					}

					// JSON数组
					JSONArray arr = null;
					// JSON对象
					JSONObject obj = null;
					try {
						arr = JSONObject.parseArray(resData.toLowerCase());
					} catch (JSONException e) {
						try {
							obj = JSONObject.parseObject(resData.toLowerCase());
						} catch (Exception ex) {
							stdout.println(NAME + ":不被处理的json\t" + url);
							return;
						}
					}
					boolean flag = false;
					if (arr != null) {
						for (int i = 0; i < arr.size(); i++) {
							if (arr.get(i) instanceof JSONObject) {
								flag = checkJson((JSONObject) arr.get(i));
							}
						}
					} else if (obj != null) {
						flag = checkJson(obj);
					}

					// 如果存在敏感字段,则添加到表格中
					if (flag) {
						count++;
						data[0] = String.valueOf(count);
						data[1] = host;
						data[2] = method;
						data[3] = path;
						data[4] = resData;
						// 编码(防止中文乱码)
						try {
							data[5] = new String(req, "utf-8");
						} catch (UnsupportedEncodingException e1) {
							data[5] = new String(req);
						}
						try {
							data[6] = new String(res, "utf-8");
						} catch (UnsupportedEncodingException e) {
							data[6] = new String(req);
						}
						model.addRow(data);
					}
				}
			}
		}
	}

	/**
	 * 检查JSON字符串中的敏感信息(递归调用)
	 * 
	 * @param obj
	 * @return
	 */
	private boolean checkJson(JSONObject obj) {
		boolean flag = false;
		for (java.util.Map.Entry<String, Object> entry : obj.entrySet()) {
			String key = entry.getKey();
			Object val = entry.getValue();
			val = val == null ? "" : val;
			if (!"".equals(val)) {
				if (val instanceof JSONArray) {
					JSONArray valArr = (JSONArray) val;
					for (int i = 0; i < valArr.size(); i++) {
						if (valArr.get(i) instanceof JSONObject) {
							checkJson((JSONObject) valArr.get(i));
						}
					}
				}
				for (String k : keys) {
					if (key.toLowerCase().indexOf(k) > -1) {
						return true;
					}
				}
			}
		}
		return flag;
	}
}