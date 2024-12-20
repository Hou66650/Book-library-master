import sqlite3

def update_image_data(book_name, image_path):
    conn = sqlite3.connect('book.db')
    cursor = conn.cursor()

    with open(image_path, 'rb') as f:
        image_data = f.read()

    try:
        cursor.execute('''
            UPDATE books
            SET data = ?
            WHERE book_name = ?
        ''', (sqlite3.Binary(image_data), book_name))
        conn.commit()
        print("Image data updated successfully.")
    except sqlite3.Error as e:
        print("Error updating image data:", e)
    finally:
        conn.close()

# 示例：更新名为 '看见' 的书的图像数据
update_image_data('活着', 'book_images/6.jpg')